module(..., package.seeall)

local constants = require('apps.lwaftr.constants')
local counter   = require('core.counter')
local lib       = require("core.lib")
local cltable   = require('lib.cltable')
local yang_util = require('lib.yang.util')
local ffi       = require('ffi')
local bit       = require('bit')
local ethernet  = require('lib.protocol.ethernet')
local ipv4      = require("lib.protocol.ipv4")
local metadata  = require('apps.rss.metadata')
local link      = require('core.link')
local packet    = require('core.packet')

local ffi_copy, ffi_cast   = ffi.copy, ffi.cast
local bit_band, bit_rshift = bit.band, bit.rshift

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local md_add, md_get, md_copy = metadata.add, metadata.get, metadata.copy
local l_transmit, l_receive, l_nreadable, l_nwriteable = link.transmit, link.receive, link.nreadable, link.nwritable
local p_free = packet.free

-- snabb-router-v1.yang
local ipv4_lpm_enum = {
   'LPM4_trie',
   'LPM4_poptrie',
   'LPM4_248',
   'LPM4_dxr',
}

-- snabb-router-v1.yang: UNIMPLEMENTED
local ipv6_lpm_enum = {}

--- # `Route` app: route traffic to an output port based on longest prefix-match

Route = {
   yang_schema = 'snabb-router-v1',
   config = {
      interfaces    = {},
      hardware      = {},
      routing       = {}
   }
}

-- TODO: Resilient Hashing / ECMP

function Route:new(config)
   local o = {
      config        = config,
      fib_v4        = nil,
      fib_v6        = nil,
      neighbours_v4 = cltable.new({ key_type = ffi.typeof('uint32_t') }), -- Default empty cltable
      neighbours_v6 = cltable.new({ key_type = ffi.typeof('uint32_t') }), -- Default empty cltable
      sync_timer    = lib.throttle(1),
      log_timer     = lib.throttle(1),
      ctr_names     = {
         'ipv4_rx',
         'ipv6_rx',
         'unkn_rx',
         'ipv4_tx',
         'ipv6_tx',
         'unkn_tx',
         'drop',
      },
      ctr = {},
      shm = {},
      links = {
         input          = {},
         input_by_name  = {},
         output         = {},
         output_by_name = {},
      },
   }

   local self = setmetatable(o, { __index = Route })

   -- Create SHM items for locally tracked counters
   for _, ctr_name in ipairs(self.ctr_names) do
      self.shm[ctr_name] = {counter, 0}
      self.ctr[ctr_name] = 0
   end

   -- Load V4 config, if specified
   self:init_v4();

   -- Load V6 config, if specified
   self:init_v6();
   return self
end

function Route:init_v4()
   if self.config.routing.family_v4 then
      local family_v4 = self.config.routing.family_v4

      -- Choose LPM implementation
      local lpm_config = assert(ipv4_lpm_enum[self.config.routing.lpm_implementation])
      local lpm_class = require('lib.lpm.'.. lpm_config:lower())[lpm_config]

      self.fib_v4 = lpm_class:new()

      self.neighbours_v4 = family_v4.neighbour

      -- Install config-loaded routes and build LPM
      for index, route in cltable.pairs(family_v4.route) do
         self:add_v4_route(route)
      end

      -- Build LPM only after all 
      self:build_v4_route()
   end
end

function Route:init_v6()
   local config = self.config
   if config.routing.family_v6 then
      print('IPv6 routing currently not supported. All IPv6 traffic will be sent to the control port.')
      self.neighbours_v6 = config.routing.family_v6.neighbour
   end
end

-- Note that this does *not* lpm:build()
function Route:add_v4_route(route)
   -- Convert integer to prefix format
   local addr = y_ipv4_ntop(route.prefix) .. '/' .. route.length
   self.fib_v4:add_string(addr, tonumber(route.next_hop))

   print('Installed v4 route ' .. addr .. ' with next-hop ' .. tostring(route.next_hop))
end

function Route:remove_v4_route(route)
   -- Convert integer to wire format
   local addr = y_ipv4_ntop(route.prefix) .. '/' .. route.length
   self.fib_v4:remove_string(addr)

   print('Uninstalled v4 route ' .. addr)
end

function Route:build_v4_route()
   return self.fib_v4:build()
end

function Route:build_v6_route()
   return self.fib_v6:build()
end

function Route:get_output_by_name(name)
   local interface_idx = self.links.output_by_name[name]
   if not interface_idx then
      return nil
   end
   return assert(self.links.output[interface_idx])
end

function Route:get_input_by_name(name)
   local interface_idx = self.links.input_by_name[name]
   if not interface_idx then
      return nil
   end
   return assert(self.links.input[interface_idx])
end

-- Sync locally stored timers to shared memory
function Route:sync_counters()
   local shm = self.shm
   local ctr = self.ctr
   for _, ctr_name in ipairs(self.ctr_names) do
      counter.set(shm[ctr_name], ctr[ctr_name]) 
   end
end

-- Forward all unknown packets to control interface
function Route:route_unknown(p)
   local ctr  = self.ctr
   local ctrl = self.output.control

   if not ctrl then
      ctr['drop'] = ctr['drop'] + 1
      return p_free(p)
   end

   ctr['unkn_tx'] = ctr['unkn_tx'] + 1

   return l_transmit(ctrl, p)
end

function Route:route_v4(p, md)
   -- Assume that no 'local' routes are installed
   -- If this is the case, we might try to forward packets
   -- which are aimed at a 'local' IP. TODO: Test this!
   local neighbour_idx = self.fib_v4:search_bytes(md.l3 + constants.o_ipv4_dst_addr)

   -- If no route found, send packet to control
   if not neighbour_idx then
      return self:route_unknown(p)
   end

   local addr = ipv4:ntop(md.l3+constants.o_ipv4_dst_addr)

   -- If route found, resolve neighbour
   local neighbour = self.neighbours_v4[neighbour_idx]
   
   -- If no neighbour found, send packet to control
   if not neighbour then
      return self:route_unknown(p)
   end

   local interface = self:get_output_by_name(neighbour.interface)

   -- If no interface found, send packet to control
   if not interface then
      return self:route_unknown(p)
   end

   local data = p.data
   
   -- At this point we know we need to forward the packet (rather than send to control)
   -- Validate it:
   local ttl = data[md.l3_offset + constants.o_ipv4_ttl]

   -- Forward packets with 0 TTL to control
   -- TODO: Maybe fix this to process in-snabb. This is a potential DoS vuln
   -- A DDoS with the TTL set correctly (i.e. so it is 0 when it hits this node)
   -- will cause all packets to be sent to Linux! It can be mitigated by rate-limiting
   -- upstream packets.                                            
   if ttl < 1 then
      return self:route_unknown(p)
   end
      
   -- Start routing packet
   local src_mac = interface.config.mac
   local dst_mac = neighbour.mac
   
   local mac_src_ptr = data + constants.o_ethernet_src_addr
   local mac_dst_ptr = data + constants.o_ethernet_dst_addr

   -- Rewrite SRC / DST MAC Addresses
   ffi_copy(mac_src_ptr, src_mac, 6)
   ffi_copy(mac_dst_ptr, dst_mac, 6)

   -- Rewrite TTL field
   data[md.l3_offset + constants.o_ipv4_ttl] = ttl - 1

   -- Recalculate checksum based on updated TTL
   local chksum_ptr = ffi_cast("uint16_t*", md.l3 + constants.o_ipv4_checksum)

   chksum_ptr[0] = chksum_ptr[0] + 0x100
   chksum_ptr[0] = bit_band(chksum_ptr[0], 0xffff) + bit_rshift(chksum_ptr[0], 16)
   chksum_ptr[0] = bit_band(chksum_ptr[0], 0xffff) + bit_rshift(chksum_ptr[0], 16)

   local ctr = self.ctr

   ctr['ipv4_tx'] = ctr['ipv4_tx'] + 1

   return l_transmit(interface.link, p)
end

-- IPv6 routing unimplemented (NO IPv6 LPM yet), route via control plane
function Route:route_v6(p, md)
   return self:route_unknown(p)
end

function Route:push ()
   local p
   local md
   local ctr   = self.ctr
   local input = self.links.input

   local ipv4_rx = 0
   local ipv6_rx = 0
   local unkn_rx = 0

   for _, link in ipairs(input) do
      local l = link.link

      for n = 1, l_nreadable(l) do
         p = l_receive(l)

         md = md_add(p, false, nil)

         -- IPv4
         if md.ethertype == 0x0800 then
            ipv4_rx = ipv4_rx + 1
            self:route_v4(p, md)

         -- IPv6
         elseif md.ethertype == 0x86dd then
            ipv6_rx = ipv6_rx + 1
            self:route_v6(p, md)

         -- Unknown (Could be arp, ospf, other multicast etc) send up to control interface
         else
            unkn_rx = unkn_rx + 1
            self:route_unknown(p)
         end
      end
   end

   ctr['ipv4_rx'] = ctr['ipv4_rx'] + ipv4_rx
   ctr['ipv6_rx'] = ctr['ipv6_rx'] + ipv6_rx
   ctr['unkn_rx'] = ctr['unkn_rx'] + unkn_rx

   if self:sync_timer() then
      self:sync_counters()
   end
end

function Route:link ()
   local interfaces = self.config.interfaces.interface

   -- Parse input links into ipairs-iterable table
   link_id = 1
   for name, l in pairs(self.input) do
      if type(name) == 'string' then
         self.links.input[link_id] = { 
            name   = name, 
            link   = l,
            config = interfaces[name], 
         }
         self.links.input_by_name[name] = link_id

         link_id = link_id + 1
      end
   end

   link_id = 1
   for name, l in pairs(self.output) do
      if type(name) == 'string' and name ~= 'control' then
         self.links.output[link_id] = { 
            name   = name, 
            link   = l,
            config = interfaces[name], 
         }
         self.links.output_by_name[name] = link_id

         link_id = link_id + 1
      end
   end
end


function selftest ()
   local random = require('apps.basic.random_source')
   local basic  = require('apps.basic.basic_apps')

   local graph = config.new()

   local v4_routes     = cltable.new({ key_type = ffi.typeof('uint32_t') })
   local v4_neighbours = cltable.new({ key_type = ffi.typeof('uint32_t') })

   v4_routes[1] = { prefix = y_ipv4_pton("1.0.0.0"), length=1, next_hop=1 }
   v4_routes[2] = { prefix = y_ipv4_pton("127.0.0.0"), length=1, next_hop=2 }

   v4_neighbours[1] = { interface = "swp1", address=y_ipv4_pton("9.9.9.9"), mac=ethernet:pton("0a:12:34:56:78:90") }
   v4_neighbours[2] = { interface = "swp2", address=y_ipv4_pton("10.10.10.10"), mac=ethernet:pton("0a:98:76:54:32:10") }

   config.app(graph, "route", Route, {
      interfaces = {
         interface = {
            swp1 = { 
               mac         = ethernet:pton("09:87:65:43:21:a0"),
               address     = y_ipv4_pton("9.9.9.8"),
               mtu         = 9014,
               passthrough = false,
            },
            swp2 = { 
               mac         = ethernet:pton("01:23:45:67:89:a0"),
               address     = y_ipv4_pton("10.10.10.9"),
               mtu         = 9014,
               passthrough = false,
            },
         }
      },
      hardware = 'test-router',
      routing = {
         lpm_implementation = 4, -- DXR (from ipv4_lpm_enum)
         family_v4 = {
            route     = v4_routes,
            neighbour = v4_neighbours,
         }
      }
   })

   config.app(graph, "swp1_in", random.RandomSource, { ratio=0.01 })
   config.app(graph, "swp2_in", random.RandomSource, { ratio=0.01 })

   config.app(graph, "swp1_out", basic.Sink)
   config.app(graph, "swp2_out", basic.Sink)

   config.app(graph, "swp1_control", basic.Sink)
   config.app(graph, "swp2_control", basic.Sink)

   config.link(graph, "swp1_in.output -> route.input")
   config.link(graph, "route.control -> swp1_control.input")

   config.link(graph, "route.swp1 -> swp1_out.input")
   config.link(graph, "route.swp2 -> swp2_out.input")

   engine.configure(graph)
   engine.main({ duration = 10, report = { showlinks = true } })
end