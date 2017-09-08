module(..., package.seeall)

local S   = require("syscall")
local h   = require("syscall.helpers")
local bit = require("bit")
local bit_band = bit.band

local nl  = S.nl
local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")
local ffi = require("ffi")
local C = ffi.C

local c, t = S.c, S.types.t

NetlinkUtil = {}

function NetlinkUtil.open_netlink()
    local tp = c.NETLINK.ROUTE
    local sock = assert(S.socket(c.AF.NETLINK, bit.bor(c.SOCK.RAW, c.SOCK.NONBLOCK), tp))
    local addr = t.sockaddr_nl()

    -- Listen for groups and interface changes
    addr.groups = c.RTMGRP.IPV4_ROUTE --, c.RTMGRP.LINK, c.RTMGRP.IPV4_IFADDR)

    local ok, err = S.bind(sock, addr)
    if not ok then
        sock:close()
        return nil, err
    end

    return sock
end

local rdump_flags = c.NLM_F('request', 'dump', 'ack')

-- Request netlink dump the full, active table
function NetlinkUtil.request_routes(sock, family, tp)
    if not sock then return nil end

    family = family or c.AF.INET
    tp     = tp or c.RTN.UNICAST

    -- Request unicast AF INET routes
    local rtm = t.rtmsg({ family = family, type = tp })

    local ok, err = nl.write(sock, nil, c.RTM.GETROUTE, rdump_flags, family, t.rtmsg, rtm)

    return ok, err
end

-- Request netlink dump interfaces
function NetlinkUtil.request_interfaces(sock)
    if not sock then return nil end

    local ok, err = nl.write(sock, nil, c.RTM.GETLINK, rdump_flags, nil, t.rtgenmsg, { rtgen_family = c.AF.PACKET })

    return ok, err
end

