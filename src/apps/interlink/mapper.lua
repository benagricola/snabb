-- This app maps interlink pairs by name and direction.

-- Use of this source code is governed by the Apache 2.0 license; see COPYING.
module(...,package.seeall)

local shm = require("core.shm")
local interlink = require("lib.interlink")

local Mapper = {
   config = {}
}

local map_links = function (links, init)
    local out = {}
    for name, l in pairs(links) do
        -- Ignore numeric indexes
        if type(name) ~= 'number' then
            local g_name = 'group/mapped_' .. name

            -- Open or create interlink
            local r = interlink.open(g_name, true)

            if init ~= nil then
                -- init will assert if link is already initialised.
                -- we want to avoid that
                pcall(interlink.init, r)
            end

            table.insert(out, { link = l, interlink = r, name = name })
        end
    end

    return out
end

function Mapper:new (conf)
   local self = { in_links = {}, out_links = {} }
   return setmetatable(self, {__index=Mapper})
end

function Mapper:link ()
    self.in_links  = map_links(self.input)
    self.out_links = map_links(self.output, true)
end

function Mapper:pull ()
   local output = self.out_links

   for _, l in ipairs(output) do
        local l, r, n = l.link, l.interlink, 0

        while not interlink.empty(r) and n < engine.pull_npackets do
            link.transmit(l, interlink.extract(r))
            n = n + 1
        end
        interlink.pull(r)
   end
end

function Mapper:push ()
   local input  = self.in_links
   for _, l in ipairs(input) do
        local l, r = l.link, l.interlink

        while not (interlink.full(r) or link.empty(l)) do
            interlink.insert(r, link.receive(l))
        end
        interlink.push(r)
   end
end

function Mapper:stop ()
   for _, l in ipairs(self.in_links) do
       shm.unmap(l.interlink)
   end
   for _, l in ipairs(self.out_links) do
       shm.unmap(l.interlink)
   end
end

return Mapper
