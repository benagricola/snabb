-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local fiber = require("lib.fibers.fiber")
local queue = require("lib.fibers.queue")
local mem = require("lib.stream.mem")
local file = require("lib.stream.file")
local ethernet = require("lib.protocol.ethernet")
local socket = require("lib.stream.socket")
local yang = require("lib.yang.yang")
local rpc = require("lib.yang.rpc")
local data = require("lib.yang.data")
local path_lib = require("lib.yang.path")
local json_lib = require("lib.ptree.json")
local common = require("program.config.common")

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump')
local rroot_flags = c.NLM_F('request', 'root')

require('lib.stream.compat').install()

local schema_name = 'snabb-router-v1'

local family_path = {
   [c.AF.INET]  = 'family-v4',
   [c.AF.INET6] = 'family-v6',
}

local snabb_config = nil

local has_changed = function(existing, new) 
   for k, v in pairs(new) do
      if existing[k] ~= v then
         print('Value for ' .. tostring(k) .. ' has changed from ' .. tostring(existing[k]) .. ' to ' .. tostring(v))
         return true
      end
   end
   return false
end

local get_existing = function(config, ...)
   for _, pitem in ipairs({...}) do
      if config ~= nil then
         config = config[pitem]
      else
         return nil
      end
   end
   return config
end

-- Update top-level config instance at `path`
local update_config = function(path)
   local xpath = '/'..path
   return { 
      method = 'set-config',
      args = { 
         schema=schema_name,
         path=xpath,
         config = common.serialize_config(snabb_config[path], schema_name, xpath)
      } 
   }
end

local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      print("[LINK] ADD", link)

      -- Loopback and non-mac interfaces not supported
      if link.loopback or not link.macaddr then return end

      local device = get_existing(snabb_config, 'hardware', 'device', link.name)

      if not device then
         print('No hardware found for link ' .. link.name .. ', ignoring...')
         return
      end

      local new = {
         index  = link.index,
         name   = link.name,
         mac    = tostring(link.macaddr),
         up     = link.flags[c.IFF.UP],
         mtu    = link.mtu,  
      }
   
      local existing = get_existing(snabb_config, 'interfaces', 'interface', link.name)
   
      if existing then
         if not has_changed(existing, new) then
            return
         end
      end
   
      snabb_config.interfaces.interface[link.name] = new

      return update_config('interfaces')
   end,
   [RTM.DELLINK] = function(link)
      print("[LINK] DEL", link)

      local existing = get_existing(snabb_config, 'interfaces', 'interface', link.name)

      if not existing then
         return nil
      end

      snabb_config.interfaces.interface[link.name] = nil

      return update_config('interfaces')
   end,
   [RTM.NEWNEIGH] = function(neigh)
      print("[NEIGH] ADD", neigh)
   end,
   [RTM.DELNEIGH] = function(neigh)
      print("[NEIGH] DEL", neigh)
   end,
   [RTM.NEWROUTE] = function(route)
      print("[ROUTE] ADD", route)
   end,
   [RTM.DELROUTE] = function(route)
      print("[ROUTE] DEL", route)
   end,
   [RTM.NEWADDR] = function(addr)
      print("[ADDR] ADD", addr)
   end,
   [RTM.DELADDR] = function(addr)
      print("[ADDR] DEL", addr)
   end
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
      "IPV4_IFADDR",
      "IPV6_IFADDR",
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
      { c.RTM.GETLINK, rdump_flags, nil, t.rtgenmsg, { rtgen_family = c.AF.PACKET } },
      { c.RTM.GETNEIGH, rdump_flags, nil, t.ndmsg, t.ndmsg() },
      -- V4
      { c.RTM.GETADDR, rdump_flags, c.AF.INET, t.ifaddrmsg, { ifa_family = c.AF.INET } },
      { c.RTM.GETADDR, rdump_flags, c.AF.INET6, t.ifaddrmsg, { ifa_family = c.AF.INET6 } },

      { c.RTM.GETROUTE, rroot_flags, c.AF.INET, t.rtmsg, t.rtmsg{ family = c.AF.INET, type = c.RTN.UNICAST } },
      { c.RTM.GETROUTE, rroot_flags, c.AF.INET6, t.rtmsg, t.rtmsg{ family = c.AF.INET6, type = c.RTN.UNICAST } },
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

            -- Only request netlink dump once snabb config is loaded
            fiber.spawn(exit_if_error(request_netlink_dump))
         end
      }
      pending_snabb_requests:put(req)
   end


   -- Received netlink events require reconfiguration of snabb via the config leader
   local function handle_netlink_events()
      while true do
         local nlmsg = nl.read(nlsock, nil, 16384, false)
         if nlmsg then
            for _, msg in ipairs(nlmsg) do
               local req = netlink_handlers[msg.nl](msg)
               if req then
                  pending_snabb_requests:put(req)
               end
            end
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
   --fiber.spawn(exit_when_finished(handle_alarms))

   fiber.main()
end