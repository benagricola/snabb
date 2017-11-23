-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S   = require("syscall")
local h   = require("syscall.helpers")
local bit = require("bit")

local now  = require("core.app").now

local ipv4 = require("lib.protocol.ipv4")
local ethernet = require("lib.protocol.ethernet")
local nlutil = require('apps.socket.nlutil').NetlinkUtil
local lpm_ipv4 = require('lib.lpm.ip4')

local nl  = S.nl

local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")
local lpm = require('lib.lpm.lpm4_trie')
local lpm_248 = require('lib.lpm.lpm4_248')
local lpm_dxr = require('lib.lpm.lpm4_dxr')
local ffi = require("ffi")
local C = ffi.C

local c, t = S.c, S.types.t

Netlink = {}

-- TODO: Implement syscall/nl.lua RTA.MULTIPATH handling (for multiple next hops / ECMP)
-- TODO: Implement functioning loopback

function Netlink:new(conf)
    local sock = nlutil.open_netlink()
    assert(sock, 'Unable to open and bind netlink socket')

    local fib_v4 = lpm.LPM4_dxr:new()

    local o = {
        sock = sock,

        fib_v4 = fib_v4,

        nexthops_v4_idx   = {},
        nexthops_v4_by_if = {},

        state = 'init',

        -- Interfaces we would like to configure internally
        interfaces = conf.interfaces or {},
        tap_map    = conf.tap_map or {},
        linux_map  = {},

        rt_pending    = 0,
        rt_build_next = 0,
        rt_build_int  = 5, -- Rebuild routing tables every 5 seconds at minimum

        -- Load full routing table by default
        reload = ((conf.reload == false) and false) or true,
    }
    return setmetatable(o, {__index = Netlink})
end

function Netlink:transition(state)
    if state and state ~= self.state then
        print('Transitioning from state ' .. self.state .. ' to ' .. state)
        self.state = state
    end
end

function Netlink:is_state(state)
    return self.state == state
end

function Netlink:state_init()
    if not self:is_state('init') then return end
    return 'interfaces'
end

function Netlink:state_interfaces()
    if not self:is_state('interfaces') then return end

    print('Requesting interfaces...')
    local ok, err = nlutil.request_interfaces(self.sock)
    if not ok then
        print('Unable to request interfaces from netlink: ', err)
        return 'interfaces'
    end
    -- Transition to routes
    return 'routes'
end

function Netlink:state_routes()
    if not self:is_state('routes') then return end

    print('Requesting routes...')
    local ok, err = nlutil.request_routes(self.sock)

    if not ok then
        print('Unable to request routes from netlink: ', err)
        return 'routes'
    end
    -- Transition to listening for updates
    return 'listen'
end

function Netlink:resolve_nexthop(wire_ip)
    local addr_index = self.fib_v4:search_bytes(wire_ip)
    if not addr_index then
        return nil
    end
    return self.nexthops_v4_idx[addr_index]
end

function Netlink:add_route(nh_details)
    local nh_idx_tab   = self.nexthops_v4_idx
    local nh_by_if_tab = self.nexthops_v4_by_if

    local prefix  = tostring(nh_details.dest) .. '/' .. nh_details.dst_len
    local gateway = tostring(nh_details.gw)
    local oif_idx = nh_details.index

    -- Validate next hop interface.
    -- If this isn't an interface we manage, ignore the route - we can't route to it anyway
    local out_index = self.linux_map[oif_idx]
    if not out_index then
        return
    end

    local intf = self.interfaces[out_index]
    if not intf then
        return
    end

    local gw_int = lpm_ipv4.parse(gateway)
    local direct = (gw_int == 0)


    -- Attempt to get next-hop index from output interface and gateway integer
    if not nh_by_if_tab[oif_idx] then
        nh_by_if_tab[oif_idx] = {}
    end

    local nh_idx = nh_by_if_tab[oif_idx][gw_int]

    -- If nh_idx not keyed by if, then insert
    if not nh_idx then
        nh_idx = #nh_idx_tab + 1
        nh_by_if_tab[oif_idx][gw_int] = nh_idx

        local gateway_wire = ipv4:pton(gateway)
        nh_idx_tab[nh_idx] = { nh = nh_details, intf = out_index, addr = gateway, direct = direct, addr_wire = gateway_wire, refcount = 1 }
    else
        -- Bump refcount
        nh_idx_tab[nh_idx].refcount = nh_idx_tab[nh_idx].refcount + 1
    end

    print('Adding ' .. prefix .. ' with gw ' .. gateway .. ' and NH index ' .. nh_idx)
    self.fib_v4:add_string(prefix, nh_idx)
    self.rt_pending = self.rt_pending + 1
end

function Netlink:del_route(nh_details)
    local nh_idx_tab   = self.nexthops_v4_idx
    local nh_by_if_tab = self.nexthops_v4_by_if
    local prefix  = tostring(nh_details.dest) .. '/' .. nh_details.dst_len
    local gateway = tostring(nh_details.gw)
    local oif_idx = nh_details.index

    local out_index = self.linux_map[oif_idx]

    if not out_index then
        return
    end

    local intf = self.interfaces[out_index]

    if not intf then
        return
    end

    local gw_int = lpm_ipv4.parse(gateway)

    if not nh_by_if_tab[oif_idx] then
        nh_by_if_tab[oif_idx] = {}
    end

    local nh_idx = nh_by_if_tab[oif_idx][gw_int]

    self.fib_v4:remove_string(prefix)
    self.rt_pending = self.rt_pending + 1

    print('Route deleted ' .. prefix .. ' via ' .. gateway .. ' (' .. intf.phy_if .. ')')

    -- If next hop exists, decrement refcount.
    -- Delete next-hop if unreferenced
    if nh_idx then
        local refcount = nh_idx_tab[nh_idx].refcount - 1
        if refcount < 1 then
            nh_by_if_tab[oif_idx][gw_int] = nil
            nh_idx_tab[nh_idx] = nil
            print('Next-hop index ' .. nh_idx .. ' no longer in use, deleting...')
        else
            nh_idx_tab[nh_idx].refcount = refcount
        end
    end
end

function Netlink:new_link(link_details)
    local name = link_details.name
    local index = link_details.ifinfo.ifi_index

    -- Convert interface tap name to snabb index
    local phy_index = self.tap_map[name]

    if not phy_index then
        print('Ignoring new link ' .. name .. ' which we dont manage')
        return
    end

    print('Interface ' .. name .. ' index mapping is ' .. phy_index .. ':' .. index .. ' (Snabb:Linux)')

    -- Link linux index to snabb index and associate
    local intf = self.interfaces[phy_index]

    if not intf then
        print('Unable to find physical interface for tap device ' .. name)
        return
    end

    self.linux_map[index] = phy_index

    link_details:address(ipv4:ntop(intf.ip) .. '/' .. intf.prefix)
    link_details:setmtu(intf.mtu)
    link_details:setmac(ethernet:ntop(intf.mac))
end

function Netlink:maybe_build()
    -- Do not rebuild if no pending route updates
    if self.rt_pending < 1 then
        return
    end

    local cur_now = now()
    if self.rt_build_next < cur_now then
        print('Rebuilding routing tables with ' .. self.rt_pending .. ' pending routes...')
        local build_start = tonumber(C.get_time_ns())
        self.fib_v4:build()
        print('Rebuild complete in ' .. (tonumber(C.get_time_ns()) - build_start) .. ' ns')
        self.rt_build_next = cur_now + self.rt_build_int
        self.rt_pending = 0
    end
end

-- Treat netlink messages like packets
-- Except 'p' as returned here is already a parsed netlink message block
function Netlink:pull ()
    -- Cannot pull with no netlink socket
    if not self.sock then return end

    local fin_state = self.state

    -- Call state function
    local sf = 'state_' .. self.state

    if type(self[sf]) == 'function' then
        fin_state = self[sf](self)
    end

    self:maybe_build()

    local limit = engine.pull_npackets
    while limit > 0 and self:can_receive() do
        limit = limit - 1
        local block = self:receive()
        if block then
            for _, msg in ipairs(block) do
                local nl = msg.nl
                if nl == c.RTM.NEWROUTE then
                    -- Resolve NH interface
                    self:add_route(msg)
                end
                if nl == c.RTM.DELROUTE then
                    self:del_route(msg)
          --        self.fib_v4:build()
                end
                if nl == c.RTM.NEWLINK then
                    self:new_link(msg)
                end
                if nl == c.RTM.DELLINK then
                    print('RTM.DELLINK NOT IMPLEMENTED')
                end
            end

        end
    end
    self:transition(fin_state)
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
    -- Use ljsyscall to read off the socket
    local d = nl.read(self.sock, nil, 8192, false)
    return d
end

function Netlink:stop()
    self.sock:close()
end

