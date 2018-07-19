module(..., package.seeall)

local cltable   = require('lib.cltable')
local lpm_ip4   = require('lib.lpm.ip4')
local lib       = require("core.lib")

local ffi       = require('ffi')

local C = ffi.C

IPv4RoutingTable = {}

local actions_by_id = {
   [0] = 'default',
   [1] = 'send_to_control',
   [2] = 'drop',
   [3] = 'route'
}

local actions = {}

for k, v in ipairs(actions_by_id) do
   actions[v] = k
end

function IPv4RoutingTable.new(config)
   local lpm_class_name = 'LPM4_'.. config.ipv4_lpm_implementation:lower()
   local lpm_class      = require('lib.lpm.'..lpm_class_name:lower())[lpm_class_name]
   local lpm_inst       = lpm_class:new()

   -- Add dummy default route
   lpm_inst:add_string('0.0.0.0/0', 0)

   local o = {
      actions                = actions,
      lpm                    = lpm_inst,
      neighbours             = {}, -- cltable.new { key_type = ffi.typeof('uint32_t') },
      gateway_counter        = #actions_by_id + 1, -- First valid gateway index
      gateway_index          = {},
      gateway_addr           = {},
      gateway_refs           = {},
      debug                  = config.debug,
      sync_timer             = lib.throttle(0.1),
      build_timer            = lib.throttle(1),
      debug_timer            = lib.throttle(0.1),
   }
   return setmetatable(o, { __index = IPv4RoutingTable })
end

-- Load relevant state
function IPv4RoutingTable:load(state)
   self.lpm             = state.lpm
   self.neighbours      = state.neighbours
   self.gateway_counter = state.gateway_counter
   self.gateway_index   = state.gateway_index
   self.gateway_addr    = state.gateway_addr
   self.gateway_refs    = state.gateway_refs
end

function IPv4RoutingTable:save()
   return {
      lpm             = state.lpm,
      neighbours      = state.neighbours,
      gateway_counter = state.gateway_counter,
      gateway_index   = state.gateway_index,
      gateway_addr    = state.gateway_addr,
      gateway_refs    = state.gateway_refs,
   }
end

-- Look up destination interface and mac
function IPv4RoutingTable:lookup(dst)
   local gateway_idx = self.lpm:search_bytes(dst)

   if not gateway_idx or gateway_idx < self.actions.route then
      return gateway_idx, nil
   end

   local gateway_addr = self.gateway_index[gateway_idx]

   if not gateway_addr then
      return self.actions.send_to_control, nil
   end

   -- If route found, resolve neighbour
   local neighbour = self.neighbours[gateway_addr]
   
   -- If no neighbour found, send packet to control
   -- If dummy neighbour (not transitioned to reachable or failed), send packet to control
   if not neighbour or not neighbour.available then
      return self.actions.send_to_control, nil
   end
   return neighbour.interface, neighbour.mac
end

function IPv4RoutingTable:add_neighbour(address, neighbour)
   self.neighbours[address] = neighbour
   -- Add /32 route for this specific neighbour
   self:add_v4_route({ dest = address..'/32', gateway = address})
end

function IPv4RoutingTable:add_route(route)
   if route.type == 'blackhole' or route.type == 'prohibit' then
      self.lpm:add_string(route.dest, self.actions.drop)
   elseif route.type == 'local' then
      self.lpm:add_string(route.dest, self.actions.send_to_control)
   else
      self:add_route_unicast(route.dest, route.gateway)
   end
   self:maybe_build()
end

-- Note that this does *not* lpm:build()
function IPv4RoutingTable:add_route_unicast(dst, gateway)
   -- Allocate index if not known already
   local index = self.gateway_addr[gateway]
   if not index then
      index = self.gateway_counter
      self.gateway_addr[gateway] = index
      self.gateway_index[index] = gateway
      self.gateway_refs[gateway] = 1
      self.gateway_counter = self.gateway_counter + 1
   else
      self.gateway_refs[gateway] = self.gateway_refs[gateway] + 1
   end
   self.lpm:add_string(dst, index)
end

function IPv4RoutingTable:remove_route(route)
   self.lpm:remove_string(route.dest)
   self.gateway_refs[route.gateway] = self.gateway_refs[route.gateway] - 1

   -- Clean up gateway indexes if not referenced by any routes
   if self.gateway_refs[route.gateway] < 1 then
      local idx = self.gateway_addr[route.gateway]
      self.gateway_index[index] = nil
      self.gateway_addr[route.gateway] = nil
      self.gateway_refs[route.gateway] = nil
   end
end

function IPv4RoutingTable:maybe_build()
   if self:build_timer() then
      local start_ns = tonumber(C.get_time_ns())
      self.lpm:build()
      if self.debug and self:debug_timer() then
         print('Built IPv4 routing table in ' .. ((tonumber(C.get_time_ns()) - start_ns)/1e6) ..'ms...')
      end
   end
end