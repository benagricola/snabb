module(..., package.seeall)

local counter   = require('core.counter')
local lib       = require("core.lib")
local cltable   = require('lib.cltable')
local yang_util = require('lib.yang.util')
local ffi       = require('ffi')
local ethernet  = require('lib.protocol.ethernet')
local ipv4      = require("lib.protocol.ipv4")
local lpm       = require('lib.lpm.lpm4_dxr')
local metadata  = require('apps.rss.metadata')
local link      = require('core.link')
local packet    = require('core.packet')

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local md_add, md_get, md_copy = metadata.add, metadata.get, metadata.copy
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
      fib_v4        = lpm.LPM4_dxr:new(),
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
         input  = {},
         output = {},
         control = nil,
      }
   }

   local self = setmetatable(o, { __index = Route })

   -- Create SHM items for locally tracked counters
   for _, ctr_name in ipairs(self.ctr_names) do
      self.shm[ctr_name] = {counter, 0}
      self.ctr[ctr_name] = 0
   end

   if config.routing.family_v4 then
      self.neighbours_v4 = config.routing.family_v4.neighbour

      -- Install config-loaded routes and build LPM
      for index, route in cltable.pairs(config.routing.family_v4.route) do

         self:add_v4_route(route)
      end

      self:build_v4_route()
   end

   if config.routing.family_v6 then
      print('IPv6 routing currently not supported. All IPv6 traffic will be sent to the control port.')
      self.neighbours_v6 = config.routing.family_v6.neighbour
   end

   return self
end

-- Note that this does *not* lpm:build()
function Route:add_v4_route(route)
   -- Convert integer to prefix format
   local addr = y_ipv4_ntop(route.prefix) .. '/' .. route.length
   print('Installing v4 route ' .. addr .. ' with next-hop ' .. tostring(route.next_hop))
   self.fib_v4:add_string(addr, tonumber(route.next_hop))
end

function Route:remove_v4_route(route)
   -- Convert integer to wire format
   local addr = y_ipv4_ntop(route.prefix) .. '/' .. route.length
   self.fib_v4:remove_string(addr)
end

function Route:build_v4_route()
   return self.fib_v4:build()
end

function Route:build_v6_route()
   return self.fib_v6:build()
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
   local ctrl = self.links.control

   if not ctrl then
      ctr['drop'] = ctr['drop'] + 1
      return p_free(p)
   end

   ctr['unkn_tx'] = ctr['unkn_tx'] + 1

   return l_transmit(ctrl, p)
end

function Route:route_v4(p, md)
   local ctr           = self.ctr
   local routes        = self.fib_v4
   local neighbour_idx = routes:search_bytes(md.l3 + 16)

   -- If no route found, send packet to control
   if not neighbour_idx then
      return self:route_unknown(p)
   end

   if self:log_timer() then
      print('Neighbour index ' .. tonumber(neighbour_idx))
   end

   -- If route found, resolve neighbour
   local neighbour = self.neighbours_v4[neighbour_idx]
   
   -- If no neighbour found, send packet to control
   if not neighbour then
      return self:route_unknown(p)
   end
   
   -- If we reach here something didn't work, free the packet!
   ctr['drop'] = ctr['drop'] + 1
   return p_free(p)
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
      local ipackets = l_nreadable(l)
      local res
      for n = 1, ipackets do
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

function Route:link (l)
   for name, l in pairs(self.input) do
      if type(name) == 'string' then
         table.insert(self.links.input, { name = name, link = l})
      end
   end

   if self.output['control'] then
      self.links.control = self.output['control']
   else
      print("No control link found, cannot handle non-ip or packets with no discernible route...")    
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
      interfaces = {},
      hardware = 'test-router',
      routing = {
         family_v4 = {
            route     = v4_routes,
            neighbour = v4_neighbours,
         }
      }
   })

   config.app(graph, "swp1_in", random.RandomSource, { ratio = 0.01 })
   config.app(graph, "swp2_in", random.RandomSource, { ratio = 0.01 })

   config.app(graph, "swp1_out", basic.Sink)
   config.app(graph, "swp2_out", basic.Sink)

   config.app(graph, "swp1_control", basic.Sink)
   config.app(graph, "swp2_control", basic.Sink)

   config.link(graph, "swp1_in.output -> route.input")
   config.link(graph, "route.control -> swp1_control.input")

   config.link(graph, "route.swp1 -> swp1_out.input")
   config.link(graph, "route.swp2 -> swp2_out.input")

   engine.configure(graph)
   engine.main({ duration = 5, report = { showlinks = true } })
end