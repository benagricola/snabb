module(...,package.seeall)

local app    = require("core.app")
local packet = require("core.packet")
local p_free = packet.free
local wutil  = require("apps.wall.util")
local pf     = require("pf")

local link = require("core.link")
local lib  = require("core.lib")
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local constants = require("apps.lwaftr.constants")
local lwutil = require("apps.lwaftr.lwutil")
local rd16, wr16, rd32, wr32 = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.wr32
local is_ipv4, is_ipv6 = lwutil.is_ipv4, lwutil.is_ipv6
local math       = require('math')
local math_min   = math.min
local ffi        = require('ffi')
local ffi_new    = ffi.new
local ffi_sizeof = ffi.sizeof
local ffi_copy   = ffi.copy

local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

--- # `DTCBridge` app: Dataplane To Controlplane Bridge
--  # Full Duplex app separating control plane and ARP traffic from routable traffic
DTCBridge = { }


function DTCBridge:new(conf)
    local o = {
        ctrl_filter     = conf.ctrl_filter,
        loopback_filter = conf.loopback_filter,
        unknown_as_ctrl = (conf.unknown_as_ctrl == false and false) or true,
        is_ctrl         = pf.compile_filter(conf.ctrl_filter or 'arp', { native = conf.native or false }),
        is_loopback     = pf.compile_filter(conf.loopback_filter or 'arp', { native = conf.native or false })
    }

    return setmetatable(o, { __index = DTCBridge })
end

function DTCBridge:check_is_ctrl(p)
    return self.is_ctrl(p.data, p.length)
end

function DTCBridge:check_is_loopback(p)
    return self.is_loopback(p.data, p.length)
end

-- Handle input packets
function DTCBridge:push()
    local l_in       = self.input.input
    local l_ctrl     = self.output.ctrl
    local l_out      = self.output.output
    local l_loopback = self.output.loopback

    -- If no control, then just forward traffic
    if not l_in or not l_out then return end

    -- We *can* drop packets here if the output links cannot accept enough
    local p_count = math_min(l_nreadable(l_in), l_nwritable(l_out))

    for _ = 1, p_count do
        local p = l_receive(l_in)

        local is_ctrl     = self:check_is_ctrl(p)
        local is_loopback = self:check_is_loopback(p)

        if not is_ctrl and not is_loopback then
            -- Otherwise transmit on output
            l_transmit(l_out, p)
        else

            -- Forward control packets to control link
            if is_ctrl and l_ctrl then
                l_transmit(l_ctrl, p)

            -- Forward loopback packets to loopback link
            elseif is_loopback and l_loopback then
                l_transmit(l_loopback, p)

            -- Discard unknown packets
            else
                if self.unknown_as_ctrl then
                    l_transmit(l_ctrl, p)
                else
                    print('WARNING: Discarding unknown traffic')
                    p_free(p)
                end
            end
        end
    end
end
