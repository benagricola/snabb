module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")

local fiber = require("lib.fibers.fiber")
local queue = require("lib.fibers.queue")
local cltable   = require('lib.cltable')
local mem = require("lib.stream.mem")
local file = require("lib.stream.file")
local sleep = require("lib.fibers.sleep")
local shm = require("core.shm")
local json = require("lib.ptree.json")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local socket = require("lib.stream.socket")
local yang = require("lib.yang.yang")
local yang_util = require("lib.yang.util")

local rpc = require("lib.yang.rpc")
local data = require("lib.yang.data")
local path_lib = require("lib.yang.path")
local common = require("program.config.common")

local alarms = require("lib.slinkd.alarms")
local util = require("lib.slinkd.util")

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump')
local rroot_flags = c.NLM_F('request', 'root')
local rupda_flags = c.NLM_F('request')


-- DO NOT CHANGE
-- This means 'dynamic' neighbours start at 3
-- Neighbour 1 means 'send to control' and does not exist
-- Neighbour 2 means 'blackhole' and does not exist
-- Neighbour 0 does not work, this is used internally by the LPM libraries
local neigh_index     = 2
local neigh_index_map = {}
local link_index_map  = {}

local schema_name = 'snabb-router-v1'

local snabb_neigh_from_netlink_neigh = function(neigh)
   local available = (neigh.state >= c.NUD.REACHABLE and neigh.state ~= c.NUD.FAILED)

   return {
      index     = neigh.index,
      interface = neigh.ifindex,
      address   = tostring(neigh.dest),
      mac       = tostring(neigh.lladdr),
      available = available,
      index     = 1,
   }
end

local snabb_route_from_netlink_route = function(route, index)
   return {
      dst     = tostring(route.dest) .. "/" .. tostring(route.dst_len),
      gateway = index,
   }
end

local snabb_link_from_netlink_link = function(link)
   return {
      index    = link.index,
      name     = link.name,
      mac      = tostring(link.macaddr),
      mtu      = link.mtu + 14, -- Linux MTU is L3 whereas Snabb mtu works at L2
      up       = link.flags[c.IFF.UP],
      state    = link.operstate
   }
end

local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      -- Loopback and non-mac interfaces not supported
      if link.loopback or not link.macaddr then return false end

      print("[LINK] ADD", link)

      local ok, device = util.get_config('/hardware/device', 'name', link.name)

      -- Just return if device is not recognized
      if not ok or not device then return false end
      
      local new     = snabb_link_from_netlink_link(link)
      local ok, old = util.get_config('/interfaces/interface', 'name', link.name)

      if not ok or not old then
         link_index_map[link.index] = link.name
         return util.add_config('/interfaces/interface', {[link.name] = new})
      end

      if util.has_changed(old, new) then
         return util.set_config('/interfaces/interface', 'name', link.name, new)
      end

      return false
   end,
   [RTM.DELLINK] = function(link)
      if link.loopback or not link.macaddr then return false end

      local ok, old = util.get_config('/interfaces/interface', 'name', link.name)

      if not (ok and old) then
         return false
      end

      print("[LINK] DEL", link)
      link_index_map[link.index] = nil
      return util.remove_config('/interfaces/interface', 'name', link.name)
   end,
   [RTM.NEWNEIGH] = function(neigh)
      print("[NEIGH] ADD", neigh)

      -- Neighbours exist on a link
      local link = link_index_map[neigh.ifindex]
      if not link then return false end

      local path = util.family_path[neigh.family]

      local new = snabb_neigh_from_netlink_neigh(neigh)

      local ok, index_map = util.get_config(path .. '/neighbour-index-by-address', 'address', new.address)

      if not ok or not index_map then
         -- If this is a new neighbour, allocate a neighbour index
         neigh_index = neigh_index + 1
         new.index = tostring(neigh_index)
         util.add_config(path ..'/neighbour',  {[new.index] = new})
         util.add_config(path ..'/neighbour-index-by-address',  {[new.address] = { index = new.index }})
         return true
      else
         local ok, old = util.get_config(path .. '/neighbour', 'index', index_map.index)
         assert(ok and old, 'Unable to get existing neighbour by index ' .. index_map.index .. ' even though it exists in the map!')
         new.index = index_map.index

         if util.has_changed(old, new) then
            return util.set_config(path .. '/neighbour', 'index', new.index, new)
         end
         return false
      end
   end,
   [RTM.DELNEIGH] = function(neigh)
      print("[NEIGH] DEL", neigh)

      local dst = tostring(neigh.dest)
      local path = util.family_path[neigh.family]

      local cur_neigh   = neigh_index_map[dst]

      local existing = util.get_config('routing', path, 'neighbour', tostring(cur_neigh))

      if not existing then
         return false
      end

      local rt_dst = dst .. "/32"

      local existing_route = util.get_config('routing', path, 'route', rt_dst)

      if existing_route then
         util.set_config(nil, 'routing', path, 'route', rt_dst)
      end

      util.set_config(nil, 'routing', path, 'neighbour', existing.index)
      return true
   end,
   [98] = function(route)
      print("[ROUTE] ADD", route, ' Type ', route.rtmsg.rtm_type)

      if route.family == c.AF.INET6 or route.rtmsg.rtm_type == c.RTN.BROADCAST or route.rtmsg.rtm_type == c.RTN.MULTICAST then
         util.print('Unsupported route type')
         return false
      end

      local local_route     = route.rtmsg.rtm_type == c.RTN.LOCAL

      -- TODO: Handle prohibit correctly
      local blackhole_route = (route.rtmsg.rtm_type == c.RTN.BLACKHOLE or route.rtmsg.rtm_type == c.RTN.PROHIBIT)

      local gateway     = tostring(route.gw)
      local dst         = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local cur_neigh   = neigh_index_map[gateway]
   
      local path = util.family_path[route.family]

      local existing_neigh 
      local existing_route = util.get_config('routing', path, 'route', dst)
      
      local new, idx


      -- Send local routes to control
      if local_route then
         idx = 1
      elseif blackhole_route then
         idx = 2
      else
         if cur_neigh then
            existing_neigh = util.get_config('routing', path, 'neighbour', tostring(cur_neigh))
         end

         -- No neighbour already learned for this route - create a dummy
         if not existing_neigh then
            neigh_index = neigh_index + 1

            existing_neigh = new_neigh(
               neigh_index,
               gateway, 
               route.index,
               "00:00:00:00:00:00",
               c.NUD.NONE
            )

            util.set_config(existing_neigh, 'routing', path, 'neighbour', tostring(neigh_index))
         end

         idx = existing_neigh.index
      end

      new = new_route(dst, tostring(idx))

      if existing_route then
         if not util.has_changed(existing_route, new) then
            return false
         end
      end

      util.set_config(new, 'routing', path, 'route', dst)
      return true
   end,
   [99] = function(route)
      print("[ROUTE] DEL", route)

      if route.family == c.AF.INET6 or route.rtmsg.rtm_type == c.RTN.BROADCAST or route.rtmsg.rtm_type == c.RTN.MULTICAST then
         return false
      end

      local dst  = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local path = util.family_path[route.family]

      local existing = util.get_config('routing', path, 'route', dst)

      if not existing then
         return false
      end

      util.set_config(nil, 'routing', path, 'route', dst)
      return true
   end,
}

local netlink_dump = {
   ["link"]       = { c.RTM.GETLINK, rdump_flags, nil, t.rtgenmsg, { rtgen_family = c.AF.PACKET } }, -- Get Links
   ["neigh"]      = { c.RTM.GETNEIGH, rdump_flags, c.AF.INET, t.ndmsg, t.ndmsg{ family = c.AF.INET } },    -- Get Neighbours
   ["ipv4-addr"]  = { c.RTM.GETADDR, rdump_flags, c.AF.INET, t.ifaddrmsg, { ifa_family = c.AF.INET } },   -- Get IPv4 Addrs
   ["ipv6-addr"]  = { c.RTM.GETADDR, rdump_flags, c.AF.INET6, t.ifaddrmsg, { ifa_family = c.AF.INET6 } }, -- Get IPv6 Addrs
   ["ipv4-route"] = { c.RTM.GETROUTE, rroot_flags, c.AF.INET, t.rtmsg, t.rtmsg{ family = c.AF.INET, type = c.RTN.UNICAST } },   -- Get IPv4 Routes
   ["ipv6-route"] = { c.RTM.GETROUTE, rroot_flags, c.AF.INET6, t.rtmsg, t.rtmsg{ family = c.AF.INET6, type = c.RTN.UNICAST } }, -- Get IPv6 Routes
}

-- Ask for netlink dump on slinkd start
function request_dump(types, output_queue)
   return util.exit_if_error(function()
      for _, type in ipairs(types) do
         util.print('Requesting netlink dump of type ' .. type)
         local args = netlink_dump[type]
         if args ~= nil then
            output_queue:put(args)
         end
      end
   end)
end

-- Try to connect to socket as soon as it opens
local function connect_netlink(type, groups)
   repeat
      -- Subscribe to default groups - LINK, ROUTE, NEIGH and ADDR
      local ok, sock = pcall(socket.connect_netlink, type, groups)

      if ok then
         return sock
      end
      sleep.sleep(0.1)
   until true
end

function return_netlink_connector(type, groups)
   local sock = nil
   return function(close)
      if close and sock then
         sock:close()
         sock = nil
      end
      if not sock then
         sock = connect_netlink(type, groups)
      end
      return sock
   end
end

function return_inbound_handler(connector, output_queue)
   return util.exit_if_error(function()
      local sock = connector()
      while true do
         local ok, nlmsg = pcall(nl.read, sock, nil, 16384, false)
         if ok and nlmsg ~= nil then
            for _, msg in ipairs(nlmsg) do
               print('Received netlink message ' .. tostring(msg.nl))
               local parser = netlink_handlers[msg.nl]
               if parser then
                  output_queue:put(parser(msg))
               else
                  print('No parser for netlink message ID ' .. tostring(msg.nl))
               end
            end
         else
            -- Trigger socket reconnect if unable to read netlink msg
            sock = connector(true)
         end
      end
   end)
end

function return_outbound_handler(connector, input_queue)
   return util.exit_if_error(function()
      local sock = connector()
      while true do
         local ok, len, err = pcall(nl.write, sock, nil, unpack(input_queue:get()))
         print(ok, len, err)
         if not ok then
            sock = connector(true)
         end
      end
   end)
end
