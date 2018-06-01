module(..., package.seeall)

local constants = require('apps.lwaftr.constants')
local counter   = require('core.counter')
local lib       = require("core.lib")
local cltable   = require('lib.cltable')
local yang_util = require('lib.yang.util')
local ffi       = require('ffi')
local bit       = require('bit')
local lpm_ip4   = require('lib.lpm.ip4')
local ethernet  = require('lib.protocol.ethernet')
local ipv4      = require("lib.protocol.ipv4")
local link      = require('core.link')
local packet    = require('core.packet')

local C = ffi.C

local ffi_copy, ffi_cast   = ffi.copy, ffi.cast
local bit_band, bit_rshift = bit.band, bit.rshift

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local l3_offset = constants.ethernet_header_size

local o_ipv4_dst_addr = l3_offset + constants.o_ipv4_dst_addr
local o_ipv4_ttl      = l3_offset + constants.o_ipv4_ttl
local o_ipv4_checksum = l3_offset + constants.o_ipv4_checksum

local uint32_t = ffi.typeof('uint32_t')
local uint32_ptr_t = ffi.typeof("$*", uint32_t)


local l_transmit, l_receive, l_nreadable, l_nwriteable = link.transmit, link.receive, link.nreadable, link.nwritable
local p_free = packet.free

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
      config               = config,
      fib_v4               = nil,
      fib_v6               = nil,
      neighbours_v4        = {}, -- Default empty cltable
      neighbours_v6        = {}, -- Default empty cltable
      sync_timer           = lib.throttle(1),
      v4_build_timer       = lib.throttle(1),
      v6_build_timer       = lib.throttle(1),
      log_timer            = lib.throttle(0.1),
      ctr_names            = {
         'ipv4_rx',
         'ipv6_rx',
         'unkn_rx',
         'ipv4_tx',
         'ipv6_tx',
         'unkn_tx',
         'drop',
      },
      ctr                  = {},
      shm                  = {},
      output_links         = {},
      output_links_by_name = {},
   }

   local self = setmetatable(o, { __index = Route })

   -- Create SHM items for locally tracked counters
   for _, ctr_name in ipairs(self.ctr_names) do
      self.shm[ctr_name] = {counter, 0}
      self.ctr[ctr_name] = 0
   end

   -- Load V4 config, if specified
   self:init_v4()

   -- Load V6 config, if specified
   self:init_v6()
   return self
end

function Route:init_v4()
   if self.config.routing.family_v4 then
      local family_v4 = self.config.routing.family_v4


      -- Choose LPM implementation
      local lpm_config = 'LPM4_'.. family_v4.lpm_implementation:lower()
      local lpm_class = require('lib.lpm.'..lpm_config:lower())[lpm_config]

      self.fib_v4 = lpm_class:new()

      -- Add default next hop with index 0 (required! do not remove)
      self.fib_v4:add_string('0.0.0.0/0', 0)

      -- Convert neighbours to integer index
      for k, v in pairs(family_v4.neighbour) do
         self.neighbours_v4[tonumber(k)] = v
      end

      -- Install config-loaded routes and build LPM
      for dst, route in pairs(family_v4.route) do
         self:add_v4_route(dst, route)
      end

      -- Build LPM only after all 
      self:build_v4_route()
   end
end

function Route:init_v6()
   local config = self.config
   if config.routing.family_v6 then
      self.neighbours_v6 = config.routing.family_v6.neighbour
   end
end

-- Note that this does *not* lpm:build()
function Route:add_v4_route(dst, route)
   -- LPM for fast routing lookup once a neighbour is identified

   -- Add route with no connected next-hop (neigh)
   self.fib_v4:add_string(dst, tonumber(route.gateway))
end

function Route:remove_v4_route(dst, route)
   -- Convert integer to wire format
   self.fib_v4:remove_string(dst)
end

function Route:build_v4_route()
   if self:v4_build_timer() then
      print('Building v4 routing table...')
      local start_ns = tonumber(C.get_time_ns())
      self.fib_v4:build()
      print('Built v4 routing table in ' .. ((tonumber(C.get_time_ns()) - start_ns)/1e6) ..'ms...')
   end
end

function Route:build_v6_route()
   if self:v6_build_timer() then
      print('Building v6 routing table...')
      local start_ns = tonumber(C.get_time_ns())
      self.fib_v6:build()
      print('Built v6 routing table in ' .. ((tonumber(C.get_time_ns()) - start_ns)/1e6) ..'ms...')
   end
end

function Route:get_output_by_name(name)
   local interface_idx = self.output_links_by_name[name]
   if not interface_idx then
      return nil
   end
   return assert(self.output_links[interface_idx])
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
function Route:route_unknown(p, data)
   local ctr  = self.ctr
   local ctrl = self.output.control

   if not ctrl then
      ctr['drop'] = ctr['drop'] + 1
      return p_free(p)
   end

   ctr['unkn_tx'] = ctr['unkn_tx'] + 1

   return l_transmit(ctrl, p)
end

function Route:route_v4(p, data)
   -- Assume that no 'local' routes are installed
   -- If this is the case, we might try to forward packets
   -- which are aimed at a 'local' IP. TODO: Test this!

   local neighbour_idx = self.fib_v4:search_bytes(data + o_ipv4_dst_addr)

   if not neighbour_idx or neighbour_idx == 0 then
      return self:route_unknown(p)
   end

   -- If route found, resolve neighbour
   local neighbour = self.neighbours_v4[neighbour_idx]
   
   -- If no neighbour found, send packet to control
   if not neighbour then
      return self:route_unknown(p)
   end

   local interface = self.output_links[neighbour.interface]

   -- If no interface found, send packet to control
   if not interface then
      return self:route_unknown(p)
   end

   -- At this point we know we need to forward the packet (rather than send to control)
   -- Validate it:
   local ttl = data[o_ipv4_ttl]

   -- Forward packets with 0 TTL to control
   -- TODO: Maybe fix this to process in-snabb. This is a potential DoS vuln
   -- A DDoS with the TTL set correctly (i.e. so it is 0 when it hits this node)
   -- will cause all packets to be sent to Linux! It can be mitigated by rate-limiting
   -- upstream packets.                                            
   if ttl < 1 then
      return self:route_unknown(p)
   end

   print('Routing packet for ' .. ipv4:ntop(data + o_ipv4_dst_addr) .. ' via gateway ' .. neighbour.address)
   
   -- Start routing packet
   -- Rewrite SRC / DST MAC Addresses
  
   ffi_copy(data + constants.o_ethernet_src_addr, interface.config.mac, 6)
   ffi_copy(data + constants.o_ethernet_dst_addr, neighbour.mac, 6)

   -- Rewrite TTL field
   data[o_ipv4_ttl] = ttl - 1

   local chksum = ffi_cast("uint16_t*", data + o_ipv4_checksum)

   -- Recalculate checksum based on updated TTL
   local sum = lib.ntohs(chksum[0]) + 0x100
   sum = lib.htons(sum + bit.rshift(sum, 16))
   sum = lib.htons(sum + bit.rshift(sum, 16))

   chksum[0] = sum

   local ctr = self.ctr

   ctr['ipv4_tx'] = ctr['ipv4_tx'] + 1

   -- TODO: Different interface link for IPv4 and IPv6 for separate Fragger paths
   return l_transmit(interface.link, p)
end

-- IPv6 routing unimplemented (NO IPv6 LPM yet), route via control plane
function Route:route_v6(p, data)
   return self:route_unknown(p)
end

function Route:push ()
   local p, data, ethertype
   local ctr   = self.ctr
   local input = self.input[1]

   local ipv4_rx, ipv6_rx, unkn_rx = 0, 0, 0

   for n = 1, l_nreadable(input) do
      p = l_receive(input)

      data = p.data

      -- Read ethertype
      ethertype = lib.ntohs(ffi_cast("uint16_t*", data + constants.o_ethernet_ethertype)[0])

      -- IPv4
      if ethertype == 0x0800 then
         ipv4_rx = ipv4_rx + 1
         self:route_v4(p, data)

      -- IPv6
      elseif ethertype == 0x86dd then
         ipv6_rx = ipv6_rx + 1
         self:route_v6(p, data)

      -- Unknown (Could be arp, ospf, other multicast etc) send up to control interface
      else
         unkn_rx = unkn_rx + 1
         self:route_unknown(p, data)
      end
   end

   ctr['ipv4_rx'] = ctr['ipv4_rx'] + ipv4_rx
   ctr['ipv6_rx'] = ctr['ipv6_rx'] + ipv6_rx
   ctr['unkn_rx'] = ctr['unkn_rx'] + unkn_rx

   if self:sync_timer() then
      self:sync_counters()
   end
end

-- Parse output links into table
function Route:link ()
   local interfaces = self.config.interfaces.interface

   for name, l in pairs(self.output) do
      if type(name) == 'string' and name ~= 'control' then
         local iface = interfaces[name]
         self.output_links[iface.index] = { 
            name   = name, 
            link   = l,
            config = iface, 
         }
         self.output_links_by_name[name] = iface.index
      end
   end
end


function selftest ()
   local random = require('apps.basic.random_source')
   local basic  = require('apps.basic.basic_apps')

   local graph = config.new()

   local neighbour_key = ffi.typeof('struct { uint32_t index; }')
   local v4_routes     = cltable.new({ key_type = ffi.typeof('uint32_t') })
   local v4_neighbours = cltable.new({ key_type = neighbour_key })

   for i = 1, 254 do
      for j = 1, 254 do
         local next_hop = (j%2) + 1
         v4_routes[i*j] = { prefix = y_ipv4_pton(i .. "." .. j .. ".0.0"), length=16, next_hop=next_hop }
      end
   end

   
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
         family_v4 = {
            lpm_implementation = "dxr", -- = 248
            route     = v4_routes,
            neighbour = v4_neighbours,
         }
      }
   })

   config.app(graph, "swp1_in", random.RandomSource, { ratio=0, unique=1000 })
   config.app(graph, "swp2_in", random.RandomSource, { ratio=0, unique=1000 })

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