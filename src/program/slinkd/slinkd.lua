-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local app = require("core.app")
local lib = require("core.lib")
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
local dataplane = require("lib.slinkd.dataplane")

local schema_name = 'snabb-router-v1'

function run(args)
   args = common.parse_command_line(args, { command='listen' })

   local dataplane_connector = dataplane.return_dataplane_connector(args.instance_id, args.schema_name, args.revision_date)
   local netlink_connector   = netlink.return_netlink_connector("ROUTE", {"LINK", "NEIGH", "IPV4_ROUTE"})
   local alarms_connector    = alarms.return_alarms_connector(args.instance_id)

   local handler = require('lib.fibers.file').install_poll_io_handler()
   require('lib.stream.compat').install()


   local config_update_requests   = queue.new()
   local pending_netlink_requests = queue.new()
   local pending_snabb_requests   = queue.new()
   local pending_snabb_replies    = queue.new()

   -- Returns a function that either opens or returns an open netlink socket
   

   -- Reads inbound netlink requests. Sends `true` on config_update_requests when config has changed
   fiber.spawn(netlink.return_inbound_handler(netlink_connector, config_update_requests))

   -- Reads outbound netlink requests from pending_netlink_requests queue and sends them to netlink socket
   fiber.spawn(netlink.return_outbound_handler(netlink_connector, pending_netlink_requests))

   -- Reads outbound dataplane requests from pending_snabb_requests and sends them to snabb config socket
   fiber.spawn(dataplane.return_outbound_handler(dataplane_connector, pending_snabb_requests, pending_snabb_replies))

   -- Reads inbound replies from dataplane and processes them
   fiber.spawn(dataplane.return_inbound_handler(dataplane_connector, pending_snabb_replies))

   -- Manages config change requests, submitting a config update when necessary
   fiber.spawn(dataplane.return_config_change_handler(config_update_requests, pending_snabb_requests))

   -- Handles inbound alarm notifications, triggering handlers
   fiber.spawn(alarms.return_inbound_handler(alarms_connector, pending_snabb_requests))

   -- Requests configuration from dataplane and requests a netlink dump once loaded
   fiber.spawn(dataplane.request_config(args.schema_name, pending_snabb_requests, function(config)
      print('Requested config and got reply')
      util.config = config
      -- Only request netlink dump once snabb config is loaded
      fiber.spawn(netlink.request_dump({'link','neigh','ipv4-route'}, pending_netlink_requests))
   end))

   fiber.main()
end