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

-- TODO: Deduplicate these maybe?
get_path_by_key = function(path, key, value)
   local ok, item = util.get_config(path, key, value)
   if not ok or not item then
      return nil
   end
   return item
end

add_or_update_path_by_key = function(path, key, new)
   local old = get_path_by_key(path, key, new[key])
   if old ~= nil then
      if util.has_changed(old, new) then
         return util.set_config(path, key, new[key], new)
      end
      return false
   end
   return util.add_config(path,  {[new[key]] = new})
end

remove_path_by_key = function(path, key, value)
   if not get_path_by_key(path, key, value) then
      return false
   end
   return util.remove_config(path, key, value)
end

get_device_by_name = function(name)
   return get_path_by_key(hardware_path, hardware_key, name)
end

get_link_by_index = function(index)
   return get_path_by_key(link_path, link_key, index)
end

add_or_update_link = function(new)
   return add_or_update_path_by_key(link_path, link_key, new)
end

remove_link_by_index = function(index)
   return remove_path_by_key(link_path, link_key, index)
end

get_neighbour_by_address = function(address)
   return get_path_by_key(neighbour_path, neighbour_key, address)
end

add_or_update_neighbour = function(new)
   return add_or_update_path_by_key(neighbour_path, neighbour_key, new)
end

remove_neighbour_by_address = function(address)
   return remove_path_by_key(neighbour_path, neighbour_key, address)
end

get_route_by_dst = function(dst)
   return get_path_by_key(route_path, route_key, dst)
end

add_or_update_route = function(new)
   return add_or_update_path_by_key(route_path, route_key, new)
end

remove_route_by_dst = function(dst)
   return remove_path_by_key(route_path, route_key, dst)
end
