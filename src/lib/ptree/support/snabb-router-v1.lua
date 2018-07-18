module(..., package.seeall)

local generic = require('lib.ptree.support').generic_schema_config_support

local function compute_config_actions(old_graph, new_graph, to_restart,
   verb, path, arg)

   print(verb, path)
   if path:match('^/routing/route') then
      local ret = {}

      if verb == 'add' then
         assert(new_graph.apps['route'])
         for k, v in pairs(new_graph.apps['route'].arg) do
            print(k, v)
         end
         for k, v in pairs(new_graph.apps['route'].class) do
            print(k, v)
         end
      end
      --table.insert(ret, {'commit', {}})
      return ret
   else
      return generic.compute_config_actions(
         old_graph, new_graph, to_restart, verb, path, arg)
   end
end

function get_config_support()
   return {
      compute_config_actions = compute_config_actions,
      compute_apps_to_restart_after_configuration_update =
         generic.compute_apps_to_restart_after_configuration_update,
      compute_state_reader = generic.compute_state_reader,
      process_states = generic.process_states,
      configuration_for_worker = generic.configuration_for_worker,
      update_mutable_objects_embedded_in_app_initargs =
         generic.update_mutable_objects_embedded_in_app_initargs,
      translators = {}
   }
end
