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
         return file.fdopen(socket, 'rdwr')
      else
         socket:close()
      end
      sleep.sleep(0.1)
   until false
end

local function return_dataplane_connector(instance_id)
   local sock = nil
   return function(close)
      if close and sock then
         sock:close()
         sock = nil
      end
      if not sock then
         sock = connect_dataplane(instance_id)
      end
      return sock
   end
end

ConfigManager = {}

function ConfigManager.new(instance_id, schema_name, revision)
   local connector = return_dataplane_connector(instance_id)
   local sock = connector()
   
   local self = setmetatable({
      connector     = connector,
      sock          = sock,
      caller        = rpc.prepare_caller('snabb-config-leader-v1'),
      schema_name   = schema_name,
      revision      = revision,
   }, { __index = ConfigManager })

   -- Attach in a fiber as this causes IO
   fiber.spawn(function()
      self:attach()
   end)
   return self
end

function ConfigManager:reconnect()
   self.sock = self.connector(true)
   return self:attach()
end

function ConfigManager:attach()
   self:send_request('attach-listener', {})
   return nil
end

function ConfigManager:send_request(method, args)
   if not args then args = {} end
   args.schema = self.schema_name
   args.revision = self.revision

   --  Send request
   local in_msg, parse_reply = rpc.prepare_call(self.caller, method, args)
   local ok, err = pcall(common.send_message, self.sock, in_msg)
   if not ok then return self:reconnect() end

   -- Read response
   local ok, out_msg = pcall(common.recv_message, self.sock)
   if not ok then return self:reconnect() end
   local ok, ret = parse_reply(out_msg)
   if not ok then
      return nil
   end
   return ret
end

function ConfigManager:get(path, key, value)
   if key then
      path = util.xpath_item(path, key, value)
   end
   return self:send_request('get-config', { path=path } )
end

function ConfigManager:add(path, config)
   return self:send_request('add-config', { path=path, config=config } )
end

function ConfigManager:set(path, key, value, config)
   if key then
      path = util.xpath_item(path, key, value)
   end
   return self:send_request('set-config', { path=path, config=config } )
end

function ConfigManager:remove(path)
   return self:send_request('remove-config', { path=path } )
end

