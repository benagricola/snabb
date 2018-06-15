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

local schema_name = 'snabb-router-v1'

-- DO NOT CHANGE
-- This means 'dynamic' neighbours start at 3
-- Neighbour 1 means 'send to control' and does not exist
-- Neighbour 2 means 'blackhole' and does not exist
-- Neighbour 0 does not work, this is used internally by the LPM libraries
local neigh_index     = 2

local neigh_index_map = {}

local link_index_map = {}

local family_path = {
   [c.AF.INET]  = 'family_v4',
   [c.AF.INET6] = 'family_v6',
}

local print = function(...)
   local o = {}
   for _, v in ipairs({...}) do
      table.insert(o, tostring(v))
   end
   io.stdout:write_chars(table.concat(o, " ") .. "\n")
   io.stdout:flush_output()
end





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

            util.snabb_config = yang.load_config_for_schema_by_name(schema_name, mem.open_input_string(cfg.config))

            if not util.snabb_config.interfaces then
               util.snabb_config.interfaces = {}
            end

            if not util.snabb_config.interfaces.interface then
               util.snabb_config.interfaces.interface = {}
            end

            if not util.snabb_config.routing then
               util.snabb_config.routing = {}
            end

            for _, fam in pairs(family_path) do
               if not util.snabb_config.routing[fam] then
                  util.snabb_config.routing[fam] = {}
               end

               if not util.snabb_config.routing[fam]['neighbour'] then
                  util.snabb_config.routing[fam]['neighbour'] = {}
               end
            end

            -- Only request netlink dump once snabb config is loaded
            fiber.spawn(netlink.request_dump('link, neigh, ipv4-route', pending_netlink_requests)))
         end
      }
      pending_snabb_requests:put(req)
   end

   local config_changed = false


   local function handle_config_changes()
      while true do
         sleep.sleep(1)
         if config_changed then
            pending_snabb_requests:put(util.update_config())
            config_changed = false
         end
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


   local nl_type   = "ROUTE"
   local nl_groups = {
      "LINK",
      "NEIGH",
      "IPV4_ROUTE",
      --"IPV6_ROUTE"
   }

   -- Reads inbound netlink requests. Sends `true` on config_update_requests when config has changed
   fiber.spawn(netlink.return_inbound_handler(nl_type, nl_groups, config_update_requests))

   -- Reads outbound netlink requests from pending_netlink_requests queue and sends them to netlink socket
   fiber.spawn(netlink.return_outbound_handler(pending_netlink_requests))

   fiber.spawn(util.exit_if_error(handle_pending_snabb_requests))
   fiber.spawn(util.exit_if_error(handle_pending_snabb_replies))
   fiber.spawn(util.exit_if_error(load_snabb_config))
   fiber.spawn(util.exit_if_error(handle_config_changes))
   fiber.spawn(alarms.return_handler(args.instance_id, pending_netlink_requests))

   fiber.main()
end