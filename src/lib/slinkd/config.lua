module(..., package.seeall)

local util = require("lib.slinkd.util")

local link_path      = '/interfaces/interface'
local link_key       = 'index'
local hardware_path  = '/hardware/device'
local hardware_key   = 'name'
local neighbour_path = '/routing/neighbour'
local neighbour_key  = 'address'
local route_path     = '/routing/route'
local route_key      = 'dest'


add_or_update_path_by_key = function(mgr, path, key, new)
   -- util.print('Adding path ' .. path .. ' by key ' .. key .. ' with value ' .. tostring(new[key]))
   local old = mgr:get(path, key, new[key])
   if old ~= nil then
      if util.has_changed(old, new) then
         return mgr:set(path, key, new[key], new)
      end
      return false
   end
   return mgr:add(path, {[new[key]] = new})
end

remove_path_by_key = function(mgr, path, key, value)
   -- util.print('Removing path ' .. path .. ' by key ' .. key .. ' with value ' .. tostring(value))
   if not mgr:get(path, key, value) then
      return false
   end
   return mgr:remove(path, key, value)
end

get_device_by_name = function(mgr, name)
   return mgr:get(hardware_path, hardware_key, name)
end

get_link_by_index = function(mgr, index)
   return mgr:get(link_path, link_key, index)
end

add_or_update_link = function(mgr, new)
   return add_or_update_path_by_key(mgr, link_path, link_key, new)
end

remove_link_by_index = function(mgr, index)
   return remove_path_by_key(mgr, link_path, link_key, index)
end

get_neighbour_by_address = function(mgr, address)
   return mgr:get(neighbour_path, neighbour_key, address)
end

add_or_update_neighbour = function(mgr, new)
   return add_or_update_path_by_key(mgr, neighbour_path, neighbour_key, new)
end

remove_neighbour_by_address = function(mgr, address)
   return remove_path_by_key(mgr, neighbour_path, neighbour_key, address)
end

get_route_by_dst = function(mgr, dst)
   return mgr:get(route_path, route_key, dst)
end

add_or_update_route = function(mgr, new)
   return add_or_update_path_by_key(mgr, route_path, route_key, new)
end

remove_route_by_dst = function(mgr, dst)
   return remove_path_by_key(mgr, route_path, route_key, dst)
end
