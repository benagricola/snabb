-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local fiber = require("lib.fibers.fiber")
local queue = require("lib.fibers.queue")
local mem = require("lib.stream.mem")
local socket = require("lib.stream.socket")
local rpc = require("lib.yang.rpc")
local data = require("lib.yang.data")
local path_lib = require("lib.yang.path")
local json_lib = require("lib.ptree.json")
local common = require("program.config.common")

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump', 'ack')
local rroot_flags = c.NLM_F('request', 'root', 'ack')

require('lib.stream.compat').install()

local function validate_config(schema_name, revision_date, path, value_str)
   local parser = common.config_parser(schema_name, path)
   local value = parser(mem.open_input_string(value_str))
   return common.serialize_config(value, schema_name, path)
end

local netlink_handlers = {
   [RTM.NEWLINK] = function(link)
      print("[LINK] ADD", link)
   end,
   [RTM.DELLINK] = function(link)
      print("[LINK] DEL", link)
   end,
   [RTM.NEWADDR] = function(addr)
      print("[ADDR] ADD", addr)
   end,
   [RTM.DELADDR] = function(addr)
      print("[ADDR] DEL", addr)
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
   end
}


local function attach_listener(leader, caller, schema_name, revision_date)
   local msg, parse_reply = rpc.prepare_call(
      caller, 'attach-listener', {schema=schema_name, revision=revision_date})
   common.send_message(leader, msg)
   return parse_reply(mem.open_input_string(common.recv_message(leader)))
end

function run(args)
   -- args = common.parse_command_line(args, { command='listen' })
   -- local caller = rpc.prepare_caller('snabb-config-leader-v1')
   -- local leader = common.open_socket_or_die(args.instance_id)
   -- attach_listener(leader, caller, args.schema_name, args.revision_date)
   
   local handler = require('lib.fibers.file').install_poll_io_handler()

   -- leader:nonblock()

   -- Subscribe to default groups - LINK, ROUTE, NEIGH and ADDR
   local nlsock = socket.connect_netlink("ROUTE", {
      "LINK",
      "NEIGH",
      "IPV4_IFADDR",
      "IPV6_IFADDR",
      "IPV4_ROUTE",
      "IPV6_ROUTE"
   })
      
   local pending_netlink_requests = queue.new()

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
      --{ c.RTM.GETROUTE, rroot_flags, c.AF.INET6, t.rtmsg, t.rtmsg{ family = c.AF.INET6, type = c.RTN.UNICAST } },
   }

   -- Ask for netlink dump on slinkd start
   local function request_netlink_dump()

      for _, req in ipairs(netlink_dump_reqs) do
         pending_netlink_requests:put(req)
      end
   end

   -- Received netlink events require reconfiguration of snabb via the config leader
   local function handle_netlink_events()
      while true do
         local nlmsg = nl.read(nlsock, nil, 16384, false)
         if nlmsg then
            for _, msg in ipairs(nlmsg) do
               local out = netlink_handlers[msg.nl](msg)
               if out then
                  print("OUT", out)
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

   -- Received alarms require reconfiguration of linux via netlink
   --local function handle_alarms()
   --end


   fiber.spawn(exit_if_error(handle_netlink_events))
   fiber.spawn(exit_if_error(handle_pending_netlink_requests))
   fiber.spawn(exit_if_error(request_netlink_dump))
   --fiber.spawn(exit_when_finished(handle_alarms))

   fiber.main()
end