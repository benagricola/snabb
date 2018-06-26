module(..., package.seeall)

local event = require("lib.slinkd.event")
local cfg   = require("lib.slinkd.config")
local S     = require("syscall")

local RTM         = S.c.RTM

NetlinkEventManager = {}

local handlers = {
   [RTM.NEWLINK] = function(config, link)
      -- Only manage links with matching devices
      if not cfg.get_device_by_name(config, link.name) then return false end
      return cfg.add_or_update_link(config, link)  
   end,
   [RTM.DELLINK] = function(config, link)
      if not cfg.get_link_by_index(config, link.index) then return false end
      return cfg.remove_link_by_index(config, link.index)
   end,
   [RTM.NEWNEIGH] = function(config, neigh)
      if not cfg.get_link_by_index(config, neigh.interface) then return false end
      -- TODO: Create Route for local neighbour
      return cfg.add_or_update_neighbour(config, neigh)
   end,
   [RTM.DELNEIGH] = function(config, neigh)
      if not cfg.get_link_by_index(config, neigh.interface) or not cfg.get_neighbour_by_address(config, neigh.address) then return false end
      -- TODO: Remove Route for local neighbour
      return cfg.remove_neighbour_by_address(config, neigh.address)
   end,
   [RTM.NEWROUTE] = function(config, route)
      return cfg.add_or_update_route(config, route)
   end,
   [RTM.DELROUTE] = function(config, route)
      return cfg.remove_route_by_dst(config, route.dst)
   end,
}

function NetlinkEventManager:new()
   return setmetatable({ handlers = handlers, name='NetlinkEventManager' }, {__index = setmetatable(NetlinkEventManager, {__index=event.EventManager})})
end
