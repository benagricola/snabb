-- Implements reading and writing from netlink sockets.
-- This class does *nothing* on its own - you must subclass
-- this and implement the `on_{new,del}_{route,link}` methods.

-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S   = require("syscall")
local h   = require("syscall.helpers")
local bit = require("bit")



local nl  = S.nl

local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")

local ffi = require("ffi")

local C = ffi.C

local c, t = S.c, S.types.t

local types = {
    route = c.NETLINK.ROUTE
}

local rdump_flags = c.NLM_F('request', 'dump', 'ack')

local open_netlink = function(tp)
    local sock = assert(S.socket(c.AF.NETLINK, bit.bor(c.SOCK.RAW, c.SOCK.NONBLOCK), tp))
    local addr = t.sockaddr_nl()

    -- Listen for groups and interface changes
    addr.groups = bit.bor(c.RTMGRP.IPV4_ROUTE, c.RTMGRP.LINK)

    local ok, err = S.bind(sock, addr)
    if not ok then
        sock:close()
        return nil, err
    end

    return sock
end


-- Request netlink dump the full, active table
function request_routes(sock, family, tp)
    if not sock then return nil end

    family = family or c.AF.INET
    tp     = tp or c.RTN.UNICAST

    -- Request unicast AF INET routes
    local rtm = t.rtmsg({ family = family, type = tp })

    local ok, err = nl.write(sock, nil, c.RTM.GETROUTE, rdump_flags, family, t.rtmsg, rtm)

    return ok, err
end


-- Request netlink dump interfaces
function request_interfaces(sock)
    if not sock then return nil end

    local ok, err = nl.write(sock, nil, c.RTM.GETLINK, rdump_flags, nil, t.rtgenmsg, { rtgen_family = c.AF.PACKET })

    return ok, err
end


Netlink = {
    config = {
        netlink_type = { default = 'route' },
    },
    shm = {
        rxnlmsgs = { counter },
        txnlmsgs = { counter },
    }
}

-- TODO: Implement syscall/nl.lua RTA.MULTIPATH handling (for multiple next hops / ECMP)

function Netlink:new(conf)
    local tp = types[conf.netlink_type]
    assert(tp, 'Netlink socket type ' .. conf.netlink_type .. ' invalid!')
    local sock = open_netlink(tp)
    assert(sock, 'Unable to open and bind netlink socket')

    local o = {
        sock = sock,
        conf = conf,
        tp   = tp,
    }

    return setmetatable(o, {__index = Netlink})
end


function Netlink:connect()
    self.sock = self.sock or open_netlink()
    return self.sock
end

-- Handle packets received from netlink socket.
-- Convert known messages to a usable struct and transmit.
function Netlink:pull ()
    self:connect()

    -- Dont pull unless both input and output open
    if self.sock then
        -- if l ~= nil then
        local limit = engine.pull_npackets
        while limit > 0 and self:can_receive() do

            local messages = self:receive()

            if messages then
                for _, msg in ipairs(messages) do
                    self:parse(msg)
                end

                counter.add(self.shm.rxnlmsgs)
                limit = limit - 1
            end
        end
    end
end


function Netlink:can_receive ()
    local t, err = S.select({readfds = {self.sock}}, 0)
    while not t and (err.AGAIN or err.INTR) do
        t, err = S.select({readfds = {self.sock}}, 0)
    end
    assert(t, err)
    return t.count == 1
end


function Netlink:receive ()
    return nl.read(self.sock, nil, 8192, false)
end

function Netlink:parse(msg)
    -- Convert netlink messages into flat struct format
    local nl = msg.nl

    if nl == c.RTM.NEWROUTE then
	-- Resolve NH interface
	return self:on_new_route(msg)
    end
    if nl == c.RTM.DELROUTE then
	return self:on_del_route(msg)
    end
    if nl == c.RTM.NEWLINK then
	return self:on_new_link(msg)
    end
    if nl == c.RTM.DELLINK then
        return self:on_del_link(msg)
    end

    error("NYI: NL Message type " .. nl)
end

function Netlink:on_new_route(msg)
    print("on_new_route must be implemented in child class")
end
function Netlink:on_del_route(msg)
    print("on_del_route must be implemented in child class")
end
function Netlink:on_new_link(msg)
    print("on_new_link must be implemented in child class")
end
function Netlink:on_del_link(msg)
    print("on_del_link must be implemented in child class")
end

function Netlink:request_interfaces()
    local sock = open_netlink(self.tp)
    local ok, err = request_interfaces(self.sock)
    if not ok then
        error('Unable to request interfaces from netlink: ', err)
    end
    sock:close()
end

function Netlink:request_routes()
    local sock = open_netlink(self.tp)
    local ok, err = request_routes(self.sock)
    if not ok then
        error('Unable to request routes from netlink: ', err)
    end
    sock:close()
end

function Netlink:stop()
    self.sock:close()
end

