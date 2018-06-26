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
local event     = require("lib.slinkd.event")
local nl_event  = require("lib.slinkd.event.netlink")
local schema_name = 'snabb-router-v1'

function run(args)
   args = common.parse_command_line(args, { command='listen' })

   local netlink_connector   = netlink.return_netlink_connector("ROUTE", {"LINK", "NEIGH", "IPV4_ROUTE"})
   local alarms_connector    = alarms.return_alarms_connector(args.instance_id)

   local handler = require('lib.fibers.file').install_poll_io_handler()
   require('lib.stream.compat').install()


   local config_update_requests   = queue.new()
   local netlink_requests         = queue.new()
   local netlink_events           = queue.new()
   local pending_snabb_replies    = queue.new()

   -- Config manager handles requests made to snabb dataplane
   local config_manager        = dataplane.ConfigManager.new(args.instance_id, schema_name)
   local netlink_event_manager = nl_event.NetlinkEventManager.new()
   
   -- Reads inbound netlink replies, creating events
   fiber.spawn(netlink.return_inbound_handler(netlink_connector, netlink_events))

   -- Handle netlink events using the dataplane config manager, and netlink event manager
   fiber.spawn(event.return_handler(netlink_events, config_manager, netlink_event_manager))

   -- Reads outbound netlink requests from netlink_requests queue and sends them to netlink socket
   fiber.spawn(netlink.return_outbound_handler(netlink_connector, netlink_requests))

   -- Handles inbound alarm notifications, creating events
   fiber.spawn(alarms.return_inbound_handler(alarms_connector, netlink_requests))

   -- Requests a netlink dump
   fiber.spawn(netlink.request_dump({'link','neigh','ipv4-route'}, netlink_requests))

   fiber.main()
end