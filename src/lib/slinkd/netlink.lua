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
local split       = S.h.split

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump')
local rroot_flags = c.NLM_F('request', 'root')
local rupda_flags = c.NLM_F('request')

local schema_name = 'snabb-router-v1'

local new_neigh = function(index, address, interface, mac, state)
   neigh_index_map[address] = index
   local available = false
   
   if (state >= c.NUD.REACHABLE and state ~= c.NUD.FAILED) then
      available = true
   end

   return {
      index     = index,
      interface = interface,
      address   = address,
      mac       = mac,
      available = available,
   }
end

local new_route = function(dst, gateway)
   return {
      dst     = dst,
      gateway = gateway,
   }
end

local new_link = function(index, name, mac, mtu, up, state)
   return {
      index    = index,
      name     = name,
      mac      = mac,
      mtu      = mtu,
      up       = up,
      state    = state,
   }
end

local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      -- Loopback and non-mac interfaces not supported
      if link.loopback or not link.macaddr then return end

      local device = util.get_config('hardware', 'device', link.name)

      if not device then return end

      print("[LINK] ADD", link)

      local new = new_link(
         link.index, 
         link.name, 
         tostring(link.macaddr),
         link.mtu + 14,
         link.flags[c.IFF.UP],
         link.operstate
      )
   
      local existing = util.get_config('interfaces', 'interface', link.name)
   
      if existing then
         if not util.has_changed(existing, new) then
            return
         end
      end
   
      util.set_config(new, 'interfaces', 'interface', link.name)
      link_index_map[link.index] = link.name

      return true
   end,
   [RTM.DELLINK] = function(link)
      local existing = util.get_config('interfaces', 'interface', link.name)

      if not existing then
         return nil
      end

      print("[LINK] DEL", link)

      util.set_config(nil, 'interfaces', 'interface', link.name)
      link_index_map[link.index] = nil
      return true
   end,
   [RTM.NEWNEIGH] = function(neigh)
      -- TODO: If LLADDR is nil but rest OK then this means lladdr has expired
      -- So we want to update the neighbour anyway.

      local link = link_index_map[neigh.ifindex]
      if not link then return end

      print("[NEIGH] ADD", neigh)

      local new, existing

      local dst = tostring(neigh.dest)
      local path = family_path[neigh.family]

      local cur_neigh = neigh_index_map[dst]

      if cur_neigh then
         existing = util.get_config('routing', path, 'neighbour', tostring(cur_neigh))
      end

      if existing then
         new = new_neigh(
            existing.index,
            dst, 
            neigh.ifindex,
            tostring(neigh.lladdr),
            neigh.state
         )

         if not util.has_changed(existing, new) then
            return
         end
      else
         neigh_index = neigh_index + 1

         new = new_neigh(
            neigh_index,
            dst, 
            neigh.ifindex,
            tostring(neigh.lladdr),
            neigh.state
         )

      end

      util.set_config(new, 'routing', path, 'neighbour', tostring(new.index))

      -- Create new route for this directly connected system
      local rt_dst = dst .. "/32"

      local new_route = new_route(rt_dst, tostring(new.index))

      local existing_route = util.get_config('routing', path, 'route', rt_dst)

      if existing_route then
         if not util.has_changed(existing_route, new_route) then
            return true
         end
      end

      util.set_config(new_route, 'routing', path, 'route', rt_dst)
      return true
   end,
   [RTM.DELNEIGH] = function(neigh)
      local dst = tostring(neigh.dest)
      local path = family_path[neigh.family]

      local cur_neigh   = neigh_index_map[dst]

      local existing = util.get_config('routing', path, 'neighbour', tostring(cur_neigh))

      if not existing then
         return nil
      end

      print("[NEIGH] DEL", neigh)

      local rt_dst = dst .. "/32"

      local existing_route = util.get_config('routing', path, 'route', rt_dst)

      if existing_route then
         util.set_config(nil, 'routing', path, 'route', rt_dst)
      end

      util.set_config(nil, 'routing', path, 'neighbour', existing.index)
      return true
   end,
   [RTM.NEWROUTE] = function(route)
      print("[ROUTE] ADD", route, ' Type ', route.rtmsg.rtm_type)

      if route.family == c.AF.INET6 or route.rtmsg.rtm_type == c.RTN.BROADCAST or route.rtmsg.rtm_type == c.RTN.MULTICAST then
         print('Unsupported route type')
         return
      end

      local local_route     = route.rtmsg.rtm_type == c.RTN.LOCAL

      -- TODO: Handle prohibit correctly
      local blackhole_route = (route.rtmsg.rtm_type == c.RTN.BLACKHOLE or route.rtmsg.rtm_type == c.RTN.PROHIBIT)

      local gateway     = tostring(route.gw)
      local dst         = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local cur_neigh   = neigh_index_map[gateway]
   
      local path = family_path[route.family]

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
            return
         end
      end

      util.set_config(new, 'routing', path, 'route', dst)
      return true
   end,
   [RTM.DELROUTE] = function(route)
      if route.family == c.AF.INET6 or route.rtmsg.rtm_type == c.RTN.BROADCAST or route.rtmsg.rtm_type == c.RTN.MULTICAST then
         return
      end

      local dst  = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local path = family_path[route.family]

      local existing = util.get_config('routing', path, 'route', dst)

      if not existing then
         return nil
      end

      print("[ROUTE] DEL", route)

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
   if type(types) == 'string' then
      types = split(",", types)
   end
   return util.exit_if_error(function()
      for _, type in ipairs(types) do
         local args = netlink_dump[type]
         if args ~= nil then
            pending_netlink_requests:put(output_queue)
         end
      end
   end
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

function return_inbound_handler(type, group, output_queue)
   return util.exit_if_error(function()
      local sock = connect_netlink(type, group)

      while true do
         local ok, nlmsg = pcall(nl.read, sock, nil, 16384, false)

         if ok and nlmsg ~= nil then
            for _, msg in ipairs(nlmsg) do
               output_queue:put(netlink_handlers[msg.nl](msg))
            end
         else
            -- Trigger socket reconnect if unable to read netlink msg
            sock:close()
            sock = connect_netlink(type, group)
         end
      end
   end)
end

function return_outbound_handler(type, group, input_queue)
   return util.exit_if_error(function()
      local sock = connect_netlink(type, group)

      while true do
         local nt = input_queue:get()
         local ok, wrok, err = pcall(nl.write, sock, nil, unpack(nt))

         if not (ok and wrok and not err) then
            sock:close()
            sock = connect_netlink(type, group)
         end
      end
   end)
end
