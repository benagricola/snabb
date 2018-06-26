module(..., package.seeall)

-- Event manager module.
-- This returns a fiber that takes a config manager class,
-- and an event type class, and processes incoming events
-- against these two.
-- The event type class consumes incoming events from a queue
-- and uses these to activate configuration changes via the 
-- config manager class.

local util = require("lib.slinkd.util")

function return_handler(input_queue, config_manager, event_manager)
   return util.exit_if_error(function()
      while true do
         local event = input_queue:get()
         local result = event_manager:handle(event, config_manager)
      end
   end)
end

EventManager = { event_key = 'type', name='EventManager', handlers = {} }

function EventManager:new()
   return setmetatable({}, { __index = EventManager })
end

function EventManager:handle(event, config)
   local event_type = event[self.event_key]
   if not event_type then
      return error('No event type found in event with key ' .. self.event_key .. ' on manager ' .. self.name)
   end

   local handler = self.handlers[event_type]
   if not handler then
      return error('Unimplemented event type ' .. event_type .. ' on manager ' .. self.name)
   end
   return handler(config, event)
end
