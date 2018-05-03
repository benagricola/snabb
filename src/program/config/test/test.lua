-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(..., package.seeall)

local yang   = require("lib.yang.yang")
local common = require("program.config.common")

function run(args)
   local opts = { command='test', with_config_file=true, is_config = false}
   local ret, args = common.parse_command_line(args, opts)

   if #args == 0 then common.show_usage(opts.command, 1, "missing config file argument") end

   local config_file = table.remove(args, 1)

   
   local schema_name = ret.schema_name

   -- Try to load schema by name 
   if not pcall(yang.load_schema_by_name, schema_name, ret.revision_date) then
      -- Schema name might be a path to the schema file
      schema_name = yang.add_schema_file(schema_name)
   end

   local data = yang.load_configuration(config_file, { 
       schema_name = schema_name, verbose = ret.verbose, 
       revision_date = ret.revision_date })

   -- Open stdout and print parsed config to it
   local file = io.open('/dev/stdout', 'w')
   yang.print_config_for_schema_by_name(schema_name, data, file)
   file.close()
end
