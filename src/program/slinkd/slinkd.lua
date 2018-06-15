-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local fiber = require("lib.fibers.fiber")
local queue = require("lib.fibers.queue")
local mem = require("lib.stream.mem")
local file = require("lib.stream.file")
local sleep = require("lib.fibers.sleep")
local yang = require("lib.yang.yang")

local data    = require("lib.yang.data")
local path_data    = require("lib.yang.path_data")

local rpc = require("lib.yang.rpc")
local common = require("program.config.common")

local alarms  = require("lib.slinkd.alarms")
local util    = require("lib.slinkd.util")
local netlink = require("lib.slinkd.netlink")

local schema_name = 'snabb-router-v1'

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

   local handler = require('lib.fibers.file').install_poll_io_handler()

   require('lib.stream.compat').install()

   leader:nonblock()
   
   local config_update_requests   = queue.new()

   local pending_netlink_requests = queue.new()
   local pending_snabb_requests   = queue.new()
   local pending_snabb_replies    = queue.new()

   local function load_snabb_config()
      local req = {
         method = 'get-config',
         args = { schema=schema_name, path='/' },
         callback = function(parse_reply, msg)
            local cfg = parse_reply(mem.open_input_string(msg))

            if not cfg then
               error('Unable to load snabb config from instance, aborting!')
            end

            util.config = yang.load_config_for_schema_by_name(schema_name, mem.open_input_string(cfg.config))

            -- Only request netlink dump once snabb config is loaded
            fiber.spawn(netlink.request_dump({'link','neigh','ipv4-route'}, pending_netlink_requests))
         end
      }
      pending_snabb_requests:put(req)
   end

   local config_changed = false


   local function handle_config_changes()
      while true do
         repeat
            local update_config = config_update_requests:get()
            if update_config then
               pending_snabb_requests:put(util.update_config())
            end
         until update_config
         sleep.sleep(1)
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

   -- Returns a function that either opens or returns an open netlink socket
   local netlink_connector = netlink.return_netlink_connector("ROUTE", {"LINK", "NEIGH", "IPV4_ROUTE"})

   -- Reads inbound netlink requests. Sends `true` on config_update_requests when config has changed
   fiber.spawn(netlink.return_inbound_handler(netlink_connector, config_update_requests))

   -- Reads outbound netlink requests from pending_netlink_requests queue and sends them to netlink socket
   fiber.spawn(netlink.return_outbound_handler(netlink_connector, pending_netlink_requests))

   fiber.spawn(util.exit_if_error(load_snabb_config))
   
   fiber.spawn(util.exit_if_error(handle_pending_snabb_requests))
   fiber.spawn(util.exit_if_error(handle_pending_snabb_replies))

   fiber.spawn(util.exit_if_error(handle_config_changes))
   fiber.spawn(alarms.return_handler(args.instance_id, pending_netlink_requests))

   fiber.main()
end