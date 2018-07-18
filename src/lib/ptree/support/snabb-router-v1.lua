local generic = require('lib.ptree.support').generic_schema_config_support

local function update_mutable_objects_embedded_in_app_initargs(
   in_place_dependencies, app_graph, schema_name, verb, path, arg)
   print(verb, path)
   return generic.update_mutable_objects_embedded_in_app_initargs(
      in_place_dependencies, app_graph, schema_name, verb, path, arg)
end

function get_config_support()
   return {
      update_mutable_objects_embedded_in_app_initargs =
         update_mutable_objects_embedded_in_app_initargs
   }
end
