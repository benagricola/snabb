-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local fiber = require("lib.fibers.fiber")
local file  = require('lib.fibers.file')
local queue = require("lib.fibers.queue")
local mem = require("lib.stream.mem")
local file = require("lib.stream.file")
local rpc = require("lib.yang.rpc")
local data = require("lib.yang.data")
local path_lib = require("lib.yang.path")
local json_lib = require("lib.ptree.json")
local common = require("program.config.common")

local function validate_config(schema_name, revision_date, path, value_str)
   local parser = common.config_parser(schema_name, path)
   local value = parser(mem.open_input_string(value_str))
   return common.serialize_config(value, schema_name, path)
end

local request_handlers = {}
function request_handlers.get(schema_name, revision_date, path)
   return {method='get-config',
           args={schema=schema_name, revision=revision_date, path=path}}
end
function request_handlers.get_state(schema_name, revision_date, path)
   return {method='get-state',
           args={schema=schema_name, revision=revision_date, path=path}}
end
function request_handlers.set(schema_name, revision_date, path, value)
   assert(value ~= nil)
   local config = validate_config(schema_name, revision_date, path, value)
   return {method='set-config',
           args={schema=schema_name, revision=revision_date, path=path,
                 config=config}}
end
function request_handlers.add(schema_name, revision_date, path, value)
   assert(value ~= nil)
   local config = validate_config(schema_name, revision_date, path, value)
   return {method='add-config',
           args={schema=schema_name, revision=revision_date, path=path,
                 config=config}}
end
function request_handlers.remove(schema_name, revision_date, path)
   return {method='remove-config',
           args={schema=schema_name, revision=revision_date, path=path}}
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
   
   local handler = file.install_poll_io_handler()

   leader:nonblock()

   -- Subscribe to default groups - LINK, ROUTE, NEIGH and ADDR
   local nlsock = netlink.open_socket()
      
   local pending_replies = queue.new()
   local function exit_when_finished(f)
      return function()
         local success, res = pcall(f)
         if not success then io.stderr:write('error: '..tostring(res)..'\n') end
         os.exit(success and 0 or 1)
      end
   end

   -- Received netlink events require reconfiguration of snabb via the config leader
   local function handle_netlink_events()
      while true do
         local nlmsg = nl.read(nlsock, nil, 8192, true)
      end
   end

   -- Received alarms require reconfiguration of linux via netlink
   local function handle_alarms()
      while true do

      end
   end


   fiber.spawn(exit_when_finished(handle_netlink_events))
   fiber.spawn(exit_when_finished(handle_alarms))

   while true do
      local sched = fiber.current_scheduler
      sched:run()
      if #sched.next == 0 then
         handler:schedule_tasks(sched, sched:now(), -1)
      end
   end
end