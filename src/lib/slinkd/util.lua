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
local data    = require("lib.yang.data")
local path_data    = require("lib.yang.path_data")
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

family_map = {
   [c.AF.INET]   = 'ipv4',
   [c.AF.INET6]  = 'ipv6'
}

family_enum = function(num)
   return family_map[num]
end

route_type_map = {
   [c.RTN.UNICAST]     = 'unicast',
   [c.RTN.LOCAL]       = 'local',
   [c.RTN.ANYCAST]     = 'anycast',
   [c.RTN.BLACKHOLE]   = 'blackhole',
   [c.RTN.UNREACHABLE] = 'unreachable',
   [c.RTN.PROHIBIT]    = 'prohibit'
}

route_type_enum = function(num)
   return route_type_map[num]
end

config = {}

print = function(...)
   local o = {}
   for _, v in ipairs({...}) do
      table.insert(o, tostring(v))
   end
   io.stdout:write_chars(table.concat(o, " ") .. "\n")
   io.stdout:flush_output()
end


has_changed = function(existing, new) 
   for k, v in pairs(new) do
      if existing[k] ~= v then
         return true
      end
   end
   return false
end

local xpath_item = function(path, key, value) return
   string.format("%s[%s=%s]", path, key, value)
end

local schema
local function get_schema()
   if not schema then
      schema = yang.load_schema_by_name(schema_name)
   end
   return schema
end

local router_grammar
local function get_grammar(root)
   if not router_grammar then
      router_grammar = data.config_grammar_from_schema(get_schema())
   end
   return router_grammar
end

get_config = function(path, key, value)
   local grammar = get_grammar()

   if key then
      path = xpath_item(path, key, value)
   end

   return pcall(path_data.resolver(grammar, path), config)
end

add_config = function(path, subconfig)
   print('Adding path ' .. path)
   local adder = path_data.adder_for_schema_by_name(schema_name, path)
   return adder(config, subconfig)
end

set_config = function(path, key, value, subconfig)
   path = xpath_item(path, key, value)

   print('Setting path ' .. path .. ', overriding existing value')
   local setter = path_data.setter_for_schema_by_name(schema_name, path)
   return setter(config, subconfig)
end

remove_config = function(path, key, value)
   path = xpath_item(path, key, value)
   print('Removing path ' .. path)
   local remover = path_data.remover_for_schema_by_name(schema_name, path)
   return remover(config)
end


-- Update top-level config instance at `path`
update_config = function()
   local xpath = '/'
   local config = common.serialize_config(config, schema_name, xpath)
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
      local res = get_config('interfaces', 'interface', res)
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
