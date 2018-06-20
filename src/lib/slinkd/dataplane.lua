module(..., package.seeall)

local S = require("syscall")
local ffi = require("ffi")

local app   = require("core.app")
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



-- Try to connect to socket as soon as it opens
local function connect_dataplane(instance_id)
   repeat

      S.signal('pipe', 'ign')
      local socket = assert(S.socket("unix", "stream"))
      local tail = instance_id..'/config-leader-socket'
      local by_name = S.t.sockaddr_un(shm.root..'/by-name/'..tail)
      local by_pid = S.t.sockaddr_un(shm.root..'/'..tail)
      if socket:connect(by_name) or socket:connect(by_pid) then
         local s =  file.fdopen(socket, 'rdwr')
         s:nonblock()
         return s
      else
         socket:close()
      end
      sleep.sleep(0.1)
   until false
end

function return_dataplane_connector(instance_id, schema_name, revision_date)
   local sock = nil
   local caller = nil
   return function(close)
      if close and sock then
         sock:close()
         sock = nil
         caller = nil
      end
      if not sock then
         sock = connect_dataplane(instance_id)
         caller = rpc.prepare_caller('snabb-config-leader-v1')

         local msg, parse_reply = rpc.prepare_call(
            caller, 'attach-listener', {schema=schema_name, revision=revision_date})
         common.send_message(sock, msg)
         parse_reply(mem.open_input_string(common.recv_message(sock)))
      end
      return sock, caller
   end
end


function request_config(schema_name, output_queue, callback)
   return util.exit_if_error(function()
      output_queue:put({
         method = 'get-config',
         args = { schema=schema_name, path='/' },
         callback = function(parse_reply, msg)
            local data = parse_reply(mem.open_input_string(msg))
            if not data then
               error('Unable to load snabb config from instance, aborting!')
            end
            local config = yang.load_config_for_schema_by_name(schema_name, mem.open_input_string(data.config))
            return callback(config)
         end
      })
   end)
end

function return_config_change_handler(input_queue, output_queue)
   return util.exit_if_error(function()
      local next_update = nil
      while true do
         if next_update and (next_update - app.now()) < 0 then
            print('Schedule expired, updating...')
            next_update = nil
            output_queue:put(util.update_config())
         elseif not next_update and input_queue:get() == true then
            print('Scheduling update')
            next_update = app.now() + 1
         end
         sleep.sleep(1)
      end
   end)
end

function return_outbound_handler(connector, input_queue, output_queue)
   return util.exit_if_error(function()
      local sock, caller = connector()
      while true do
         local nt = input_queue:get()
         local msg, parse_reply = rpc.prepare_call(
            caller, nt.method, nt.args)

         if not nt.callback then
            output_queue:put({ callback = nil })
         else
            output_queue:put({callback = nt.callback, parse_reply = parse_reply})
         end

         -- Call leader
         local ok, msg = pcall(common.send_message, sock, msg)

         -- Reconnect if send_message errored
         if not ok then
            sock, caller = connector(true)
         end
      end
   end)
end

function return_inbound_handler(connector, input_queue)
   return util.exit_if_error(function()
      local sock, caller = connector()
      while true do
         local res = input_queue:get()

         local ok, msg = pcall(common.recv_message, sock)
         print('Received message')
         if not ok then
            sock, caller = connector(true)
         elseif res.callback then
            res.callback(res.parse_reply, msg)
         end
      end
   end)
end
