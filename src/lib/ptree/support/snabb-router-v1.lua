module(..., package.seeall)

local rtv4    = require('lib.slinkd.routing_table').IPv4RoutingTable
local generic = require('lib.ptree.support').generic_schema_config_support


local routing_table_instance
local function get_routing_table_instance(conf)
   if routing_table_instance == nil then
      -- Instantiate new routing table
      routing_table_instance = rtv4:new(conf)
   end
   return routing_table_instance
end

local function compute_config_actions(old_graph, new_graph, to_restart, verb, path, arg)
   local actions = {}
   actions = engine.compute_config_actions(old_graph, new_graph)
   table.insert(actions, {'commit', {}})
   return actions
end

function get_config_support()
   return {
      compute_config_actions                             = compute_config_actions,
      configuration_for_worker                           = generic.configuration_for_worker,
      compute_state_reader                               = generic.compute_state_reader,
      update_mutable_objects_embedded_in_app_initargs    = function () end,
      compute_apps_to_restart_after_configuration_update = function () end,
      translators = {}
   }
end
