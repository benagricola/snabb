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

local y_ipv4_pton, y_ipv4_ntop = yang_util.ipv4_pton, yang_util.ipv4_ntop

local c           = S.c
local nl          = S.nl
local t           = S.t

local RTM         = c.RTM
local rdump_flags = c.NLM_F('request', 'dump')
local rroot_flags = c.NLM_F('request', 'root')
local rupda_flags = c.NLM_F('request')

local schema_name = 'snabb-router-v1'

snabb_config = {}

has_changed = function(existing, new) 
   for k, v in pairs(new) do
      if existing[k] ~= v then
         return true
      end
   end
   return false
end

get_config = function(config, ...)
   for _, pitem in ipairs({...}) do
      if config ~= nil then
         config = config[pitem]
      else
         return nil
      end
   end
   return config
end

set_config = function(config, value, ...)
   local vars = {...}
   local v = #vars-1
   for i=1,v do
      local p = vars[i]
      if config ~= nil then
         config = config[p]
      else
         return nil
      end
   end
   config[vars[v+1]] = value
end


-- Update top-level config instance at `path`
update_config = function()
   local xpath = '/'
   local config = common.serialize_config(snabb_config, schema_name, xpath)
   return { 
      method = 'set-config',
      args = { 
         schema=schema_name,
         path=xpath,
         config = config,
      },
      -- Error out on failure to set config
      callback = function(parse_reply, msg)
         local ret = parse_reply(mem.open_input_string(msg))
         if ret.status ~= 0 then
            error('Unable to update dataplane config: ' .. ret.error)
         end
         print('[CONFIG] UPDATE')
      end
   }
end


get_interface_from_resource = function(resource)
   for _, res in ipairs(resource) do
      local res = get_config(snabb_config, 'interfaces', 'interface', res)
      if res then
         return res
      end
   end
end

exit_if_error = function(f)
   return function()
      local success, res = pcall(f)
      if not success then
         io.stderr:write('error: '..tostring(res)..'\n')
         os.exit(1)
      end
   end
end
