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
local config = require("lib.slinkd.config")

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
--local neigh_index     = 2

local schema_name = 'snabb-router-v1'

local link_from_netlink = function(link)
   if link.loopback or not link.macaddr then 
      return nil 
   end
   util.print('[LINK]', link)
   return {
      index    = tostring(link.index),
      name     = link.name,
      mac      = tostring(link.macaddr),
      mtu      = link.mtu + 14, -- Linux MTU is L3 whereas Snabb mtu works at L2
      up       = link.flags[c.IFF.UP],
      state    = link.operstate
   }
end

local neighbour_from_netlink = function(neigh)
   util.print('[NEIGH]', neigh)

   local available = (neigh.state >= c.NUD.REACHABLE and neigh.state ~= c.NUD.FAILED)

   return {
      interface = tostring(neigh.ifindex),
      address   = tostring(neigh.dest),
      mac       = tostring(neigh.lladdr),
      available = available,
      family    = util.family_enum(neigh.family),
   }
end

local route_from_netlink = function(route)
   local type = route.rtmsg.rtm_type

   if type >= c.RTN.THROW or type == c.RTN.BROADCAST 
   or type == c.RTN.MULTICAST or type == c.RTN.UNSPEC then
      return nil
   end

   util.print('[ROUTE]', route)

   return {
      dest    = tostring(route.dest) .. '/' .. tostring(route.dst_len),
      gateway = tostring(route.gw),
      family  = util.family_enum(route.family),
      type    = util.route_type_enum(type)
   }
end

local netlink_parsers = {
   [RTM.NEWLINK]  = link_from_netlink,
   [RTM.DELLINK]  = link_from_netlink,
   [RTM.NEWNEIGH] = neighbour_from_netlink,
   [RTM.DELNEIGH] = neighbour_from_netlink,
   [RTM.NEWROUTE] = route_from_netlink,
   [RTM.DELROUTE] = route_from_netlink,
}

local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      -- Only manage links with matching devices
      if not config.get_device_by_name(link.name) then return false end
      return config.add_or_update_link(link)  
   end,
   [RTM.DELLINK] = function(link)
      if not config.get_link_by_index(link.index) then return false end
      return config.remove_link_by_index(link.index)
   end,
   [RTM.NEWNEIGH] = function(neigh)
      if not config.get_link_by_index(neigh.interface) then return false end
      -- TODO: Create Route for local neighbour
      return config.add_or_update_neighbour(neigh)
   end,
   [RTM.DELNEIGH] = function(neigh)
      if not config.get_link_by_index(neigh.interface) or not config.get_neighbour_by_address(neigh.address) then return false end
      -- TODO: Remove Route for local neighbour
      return config.remove_neighbour_by_address(neigh.address)
   end,
   [RTM.NEWROUTE] = function(route)
      return config.add_or_update_route(route)
   end,
   [RTM.DELROUTE] = function(route)
      return config.remove_route_by_dst(route.dst)
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
   until false
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
         -- Trigger socket reconnect if unable to read netlink msg
         if not ok then
            sock = connector(true)
         elseif nlmsg ~= nil then
            for _, msg in ipairs(nlmsg) do
               local parser  = netlink_parsers[msg.nl]
               local handler = netlink_handlers[msg.nl]
               -- print('NLMSG: ' .. tostring(msg.nl))
               if parser then
                  msg = parser(msg)
               end
               if msg ~= nil then
                  -- print('PARSED: ')
                  -- for k, v in pairs(msg) do
                  --    print(k, v)
                  -- end
                  output_queue:put(handler(msg))
               end
            end
         end
      end
   end)
end

function return_outbound_handler(connector, input_queue)
   return util.exit_if_error(function()
      local sock = connector()
      while true do
         local ok, len, err = pcall(nl.write, sock, nil, unpack(input_queue:get()))
         if not ok then
            sock = connector(true)
         end
      end
   end)
end
