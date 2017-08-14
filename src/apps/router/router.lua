module(...,package.seeall)

local app = require("core.app")
local arp = require("apps.lwaftr.arp")
local packet = require("core.packet")
local link = require("core.link")
local ffi = require("ffi")
local transmit, receive, nreadable = link.transmit, link.receive, link.nreadable

--- # `zAPIRouter` app: Route packets based on routing table learned via zAPI

zAPIRouter = {}

function zAPIRouter:new(conf)
    local o = {}
    local ctrl_ips = {}

    for ip in conf.ctrl_ips do
        ctrl_ips[ip] = true
    end
    o['ctrl_ips'] = ctrl_ips

    return setmetatable(o, {__index=zAPIRouter})
end

function zAPIRouter:process_arp(p)
    if not arp.is_arp(p) then
        return nil
    end

    if arp.is_arp_request(p) then
        print("Arp request received")
    end
end

function zAPIRouter:process_ctrl()
   local ctrl_lnk = self.input.ctrl
   local readable = nreadable(ctrl_lnk)

   -- Process packets on control interfaces
   for _ = 1, readable do
       -- Receive packet
       local p = receive(ctrl_lnk)
       self:process_arp(p)

       packet.free(p)
   end
end

function zAPIRouter:push()
    self:process_ctrl()
end

