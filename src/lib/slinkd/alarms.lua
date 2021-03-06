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
local util = require("lib.slinkd.util")

local netlink = require("lib.slinkd.netlink")
local config = require("lib.slinkd.config")

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM

local rupda_flags = c.NLM_F('request')

local IF_OPER_UP      = 6
local IF_OPER_DORMANT = 5

local get_interface_from_resource = function(resource)
   for _, res in ipairs(resource) do
      local res = config.get_link_by_index(res)
      if res then
         return res
      end
   end
end

-- Try to connect to socket as soon as it opens
local function connect_notifications(instance_id)
   local tail = instance_id .. '/notifications'

   repeat
      -- Subscribe to notifications (alarms) from snabb
      local ok, sock = pcall(socket.connect_unix, shm.root..'/by-name/' .. tail)

      if ok then
         return sock
      end
      sleep.sleep(0.1)
   until false
end

function return_alarms_connector(instance_id)
   local sock = nil
   return function(close)
      if close and sock then
         sock:close()
         sock = nil
      end
      if not sock then
         sock = connect_notifications(instance_id)
      end
      return sock
   end
end

local event_handlers = {
   ['alarm-notification'] = {
      ['phy-down'] = function(alarm)
         local interface = get_interface_from_resource(alarm.alt_resource)
         
         if not interface then
            return print('Alarm notification for unknown interface ', alarm.resource)
         end

         -- If link is up, set down
         if interface.state == IF_OPER_UP then
            print('[ALARM] PHY DOWN ' .. interface.name)
            return { RTM.NEWLINK, rupda_flags, nil, t.ifinfomsg, { ifi_index = interface.index }, 'operstate', IF_OPER_DORMANT }
         else
            print('[ALARM] PHY UP ' .. interface.name)
            return { RTM.NEWLINK, rupda_flags, nil, t.ifinfomsg, { ifi_index = interface.index, ifi_flags = c.IFF.UP, ifi_change = c.IFF.UP }, 'operstate', IF_OPER_UP }
         end
      end,
   }
}

-- Received alarms may reconfigure linux via netlink
function return_inbound_handler(connector, output_queue)
   return util.exit_if_error(function()
      local sock = connector()
      while true do
         local ok, event = pcall(json.read_json, sock)

         if not ok then
            sock = connector(true)
         elseif ok and event ~= nil then
            local handler = event_handlers[event.event][event.alarm_type_id]
            if handler then 
               local req = handler(event)
               if req then
                  output_queue:put(req)
               end 
            end
         end
      end
   end)
end