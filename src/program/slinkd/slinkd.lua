-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local fiber = require("lib.fibers.fiber")
local queue = require("lib.fibers.queue")
local cltable   = require('lib.cltable')
local mem = require("lib.stream.mem")
local file = require("lib.stream.file")
local sleep = require("lib.fibers.sleep")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local socket = require("lib.stream.socket")
local yang = require("lib.yang.yang")
local yang_util = require("lib.yang.util")
local rpc = require("lib.yang.rpc")
local data = require("lib.yang.data")
local path_lib = require("lib.yang.path")
local json_lib = require("lib.ptree.json")
local common = require("program.config.common")

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump')
local rroot_flags = c.NLM_F('request', 'root')

require('lib.stream.compat').install()

local schema_name = 'snabb-router-v1'

-- DO NOT CHANGE
-- This means 'dynamic' neighbours start at 2
-- Neighbour 1 means 'send to control' and does not exist
-- Neighbour 0 does not work, this is used internally by the LPM libraries
local neigh_index     = 1

local neigh_index_map = {

}

local family_path = {
   [c.AF.INET]  = 'family_v4',
   [c.AF.INET6] = 'family_v6',
}

local snabb_config = nil

local has_changed = function(existing, new) 
   for k, v in pairs(new) do
      if existing[k] ~= v then
         print('Key ' .. tostring(k) .. ' has changed value from ' .. tostring(existing[k]) .. ' to ' .. tostring(v))
         return true
      end
   end
   return false
end

local get_config = function(config, ...)
   for _, pitem in ipairs({...}) do
      if config ~= nil then
         config = config[pitem]
      else
         return nil
      end
   end
   return config
end

local set_config = function(config, value, ...)
   local vars = {...}
   local v = #vars-1
   for i=1,v do
      local p = vars[i]
      if config ~= nil then
         config = config[p]
      else
         return nil
      end
   end
   config[vars[v+1]] = value
end

-- Update top-level config instance at `path`
local update_config = function()
   local xpath = '/'
   local config = common.serialize_config(snabb_config, schema_name, xpath)
   return { 
      method = 'set-config',
      args = { 
         schema=schema_name,
         path=xpath,
         config = config,
      },
      -- Error out on failure to set config
      callback = function(parse_reply, msg)
         local ret = parse_reply(mem.open_input_string(msg))
         if ret.status ~= 0 then
            error('Unable to update dataplane config: ' .. ret.error)
         end
      end
   }
end

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

local new_link = function(index, name, mac, mtu, up)
   return {
      index = index,
      name  = name,
      mac   = mac,
      up    = up,
      mtu   = mtu,
   }
end



local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      print("[LINK] ADD", link)

      -- Loopback and non-mac interfaces not supported
      if link.loopback or not link.macaddr then return end

      local device = get_config(snabb_config, 'hardware', 'device', link.name)

      if not device then
         print('No hardware found for link ' .. link.name .. ', ignoring...')
         return
      end

      local new = new_link(
         link.index, 
         link.name, 
         tostring(link.macaddr),
         link.mtu + 14,
         link.flags[c.IFF.UP]
      )
   
      local existing = get_config(snabb_config, 'interfaces', 'interface', link.name)
   
      if existing then
         if not has_changed(existing, new) then
            return
         end
      end
   
      set_config(snabb_config, new, 'interfaces', 'interface', link.name)

      return true
   end,
   [RTM.DELLINK] = function(link)
      print("[LINK] DEL", link)

      local existing = get_config(snabb_config, 'interfaces', 'interface', link.name)

      if not existing then
         return nil
      end

      set_config(snabb_config, nil, 'interfaces', 'interface', link.name)
      return true
   end,
   [RTM.NEWNEIGH] = function(neigh)
      print("[NEIGH] ADD", neigh)

      -- TODO: If LLADDR is nil but rest OK then this means lladdr has expired
      -- So we want to update the neighbour anyway.

      -- if not neigh.lladdr then return end

      local new

      local dst = tostring(neigh.dest)

      local path = family_path[neigh.family]

      local existing

      -- TODO: Insert a new route for locally learned neighbours? 

      local cur_neigh = neigh_index_map[dst]

      if cur_neigh then
         existing = get_config(snabb_config, 'routing', path, 'neighbour', tostring(cur_neigh))
      end

      local index

      if existing then
         new = new_neigh(
            existing.index,
            dst, 
            neigh.ifindex,
            tostring(neigh.lladdr),
            neigh.state
         )

         if not has_changed(existing, new) then
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

      set_config(snabb_config, new, 'routing', path, 'neighbour', tostring(new.index))

      -- Create new route for this directly connected system
      local rt_dst = dst .. "/32"
      print(rt_dst, tostring(new.index))
      local new_route = new_route(rt_dst, tostring(new.index))

      local existing_route = get_config(snabb_config, 'routing', path, 'route', rt_dst)

      if existing_route then
         if not has_changed(existing_route, new_route) then
            return true
         end
      end

      set_config(snabb_config, new_route, 'routing', path, 'route', rt_dst)
      return true
   end,
   [RTM.DELNEIGH] = function(neigh)
      print("[NEIGH] DEL", neigh)

      local dst = tostring(neigh.dest)
      local path = family_path[neigh.family]

      local cur_neigh   = neigh_index_map[dst]

      local existing = get_config(snabb_config, 'routing', path, 'neighbour', tostring(cur_neigh))

      if not existing then
         return nil
      end

      local rt_dst = dst .. "/32"

      local existing_route = get_config(snabb_config, 'routing', path, 'route', rt_dst)

      if existing_route then
         set_config(snabb_config, nil, 'routing', path, 'route', rt_dst)
      end

      set_config(snabb_config, nil, 'routing', path, 'neighbour', existing.index)
      return true
   end,
   [RTM.NEWROUTE] = function(route)
      print("[ROUTE] ADD", route, ' Type ', route.rtmsg.rtm_type)

      if route.family == c.AF.INET6 then
         print('IPv6 routing not supported...')
         return
      end

      local local_route = route.rtmsg.rtm_type == c.RTN.LOCAL


      local gateway     = tostring(route.gw)
      local dst         = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local cur_neigh   = neigh_index_map[gateway]
   
      local path = family_path[route.family]
      local existing_neigh 

      local existing_route = get_config(snabb_config, 'routing', path, 'route', dst)
      
      local new

      -- Send local routes to control
      if local_route then
         new = new_route(dst, tostring(1))
      else
         if cur_neigh then
            existing_neigh = get_config(snabb_config, 'routing', path, 'neighbour', tostring(cur_neigh))
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

            set_config(snabb_config, existing_neigh, 'routing', path, 'neighbour', tostring(neigh_index))
         end

         new = new_route(dst, tostring(existing_neigh.index))
      end

      if existing_route then
         if not has_changed(existing_route, new) then
            return
         end
      end

      set_config(snabb_config, new, 'routing', path, 'route', dst)
      return true
   end,
   [RTM.DELROUTE] = function(route)
      print("[ROUTE] DEL", route)

      if route.family == c.AF.INET6 then
         print('IPv6 routing not supported...')
         return
      end

      local dst  = tostring(route.dest) .. "/" .. tostring(route.dst_len)
      local path = family_path[route.family]

      local existing = get_config(snabb_config, 'routing', path, 'route', dst)

      if not existing then
         print('No existing route found for ' .. dst)
         return nil
      end

      set_config(snabb_config, nil, 'routing', path, 'route', dst)
      return true
   end,
}

local function attach_listener(leader, caller, schema_name, revision_date)
   local msg, parse_reply = rpc.prepare_call(
      caller, 'attach-listener', {schema=schema_name, revision=revision_date})
   common.send_message(leader, msg)
   return parse_reply(mem.open_input_string(common.recv_message(leader)))
end

function run(args)
   args = common.parse_command_line(args, { command='listen' })
   local caller = rpc.prepare_caller('snabb-config-leader-v1')
   local leader = common.open_socket_or_die(args.instance_id)
   attach_listener(leader, caller, args.schema_name, args.revision_date)
   
   local client_tx = file.fdopen(S.stdout)

   local handler = require('lib.fibers.file').install_poll_io_handler()

   leader:nonblock()

   -- Subscribe to default groups - LINK, ROUTE, NEIGH and ADDR
   local ok, nlsock = pcall(socket.connect_netlink, "ROUTE", {
      "LINK",
      "NEIGH",
      -- We don't need local IPaddr info right now
      -- "IPV4_IFADDR",
      -- "IPV6_IFADDR",
      "IPV4_ROUTE",
      "IPV6_ROUTE"
   })

   if not ok then
      error("Could not connect to netlink socket\n")
      os.exit(1)
   end
      
   local pending_netlink_requests = queue.new()
   local pending_snabb_requests   = queue.new()
   local pending_snabb_replies    = queue.new()

   local function exit_if_error(f)
      return function()
         local success, res = pcall(f)
         if not success then
            io.stderr:write('error: '..tostring(res)..'\n')
            os.exit(1)
         end
      end
   end

   -- nlmsg    (ntype, flags, af, ...)
   -- nl.write (sock, dest, ntype, flags, af, ...)
   local netlink_dump_reqs = {
      { c.RTM.GETLINK, rdump_flags, nil, t.rtgenmsg, { rtgen_family = c.AF.PACKET } }, -- Get Links
      { c.RTM.GETNEIGH, rdump_flags, nil, t.ndmsg, t.ndmsg() },                        -- Get Neighbours

      --{ c.RTM.GETADDR, rdump_flags, c.AF.INET, t.ifaddrmsg, { ifa_family = c.AF.INET } },   -- Get IPv4 Addrs
      --{ c.RTM.GETADDR, rdump_flags, c.AF.INET6, t.ifaddrmsg, { ifa_family = c.AF.INET6 } }, -- Get IPv6 Addrs

      { c.RTM.GETROUTE, rroot_flags, c.AF.INET, t.rtmsg, t.rtmsg{ family = c.AF.INET, type = c.RTN.UNICAST } },   -- Get IPv4 Routes
      { c.RTM.GETROUTE, rroot_flags, c.AF.INET6, t.rtmsg, t.rtmsg{ family = c.AF.INET6, type = c.RTN.UNICAST } }, -- Get IPv6 Routes
   }

   -- Ask for netlink dump on slinkd start
   local function request_netlink_dump()
      for _, req in ipairs(netlink_dump_reqs) do
         pending_netlink_requests:put(req)
      end
   end

   local function load_snabb_config()
      local req = {
         method = 'get-config',
         args = { schema=schema_name, path='/' },
         callback = function(parse_reply, msg)
            local cfg = parse_reply(mem.open_input_string(msg))

            if not cfg then
               error('Unable to load snabb config from instance, aborting!')
            end

            snabb_config = yang.load_config_for_schema_by_name(schema_name, mem.open_input_string(cfg.config))

            if not snabb_config.interfaces then
               snabb_config.interfaces = {}
            end

            if not snabb_config.interfaces.interface then
               snabb_config.interfaces.interface = {}
            end

            if not snabb_config.routing then
               snabb_config.routing = {}
            end

            for _, fam in pairs(family_path) do
               if not snabb_config.routing[fam] then
                  snabb_config.routing[fam] = {}
               end

               if not snabb_config.routing[fam]['neighbour'] then
                  snabb_config.routing[fam]['neighbour'] = {}
               end
            end

            -- Only request netlink dump once snabb config is loaded
            fiber.spawn(exit_if_error(request_netlink_dump))
         end
      }
      pending_snabb_requests:put(req)
   end


   local config_changed = false

   -- Received netlink events require reconfiguration of snabb via the config leader
   local function handle_netlink_events()
      local last_update = engine.now()
      while true do
         local nlmsg = nl.read(nlsock, nil, 16384, false)
         if nlmsg then
            for _, msg in ipairs(nlmsg) do
               local req = netlink_handlers[msg.nl](msg)
               if req then
                  config_changed = true
               end
            end
         end
      end
   end

   local function handle_config_changes()
      while true do
         sleep.sleep(1)
         if config_changed then
            print('Updating config...')
            pending_snabb_requests:put(update_config())
            config_changed = false
         end
      end
   end

   local function handle_pending_netlink_requests()
      while true do
         local nt = pending_netlink_requests:get()
         nl.write(nlsock, nil, unpack(nt))
      end
   end

   local function handle_pending_snabb_requests()
      while true do
         local nt = pending_snabb_requests:get()

         local msg, parse_reply = rpc.prepare_call(
            caller, nt.method, nt.args)

         if not nt.callback then
            pending_snabb_replies:put({ callback = nil })
         else
            pending_snabb_replies:put({callback = nt.callback, parse_reply = parse_reply})
         end

         -- Call leader
         common.send_message(leader, msg)
      end
   end

   local function handle_pending_snabb_replies()
      while true do
         local res = pending_snabb_replies:get()
         if res.callback then
            res.callback(res.parse_reply, common.recv_message(leader))
         else
            common.recv_message(leader)
         end
      end
   end


   -- Received alarms require reconfiguration of linux via netlink
   --local function handle_alarms()
   --end


   fiber.spawn(exit_if_error(handle_netlink_events))
   fiber.spawn(exit_if_error(handle_pending_netlink_requests))
   fiber.spawn(exit_if_error(handle_pending_snabb_requests))
   fiber.spawn(exit_if_error(handle_pending_snabb_replies))
   fiber.spawn(exit_if_error(load_snabb_config))
   fiber.spawn(exit_if_error(handle_config_changes))
   --fiber.spawn(exit_when_finished(handle_alarms))

   fiber.main()
end