-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S   = require("syscall")
local h   = require("syscall.helpers")
local bit = require("bit")

local now  = require("core.app").now

local ipv4 = require("lib.protocol.ipv4")
local nlutil = require('apps.socket.nlutil').NetlinkUtil
local lpm_ipv4 = require('lib.lpm.ip4')

local nl  = S.nl

local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")
local lpm = require('lib.lpm.lpm4_trie')
local lpm_248 = require('lib.lpm.lpm4_248')
local ffi = require("ffi")
local C = ffi.C

local c, t = S.c, S.types.t

Netlink = {}

-- TODO: Implement syscall/nl.lua RTA.MULTIPATH handling (for multiple next hops / ECMP)
-- TODO: Implement functioning loopback

function Netlink:new(conf)
    local sock = nlutil.open_netlink()
    assert(sock, 'Unable to open and bind netlink socket')

    local fib_v4 = lpm.LPM4_trie:new()
    local fib_v6 = lpm.LPM4_trie:new()

    local o = {
        sock = sock,

        fib_v4 = fib_v4,
        fib_v6 = fib_v6,

        nexthops_v4_idx  = {},
        nexthops_v4_addr = {},
        nexthops_v6_idx  = {},
        nexthops_v6_addr = {},

        state = 'state_init',

        -- Interfaces we would like to configure internally
        interfaces = conf.interfaces or {},
        tap_map    = conf.tap_map or {},
        linux_map  = {},

        rt_pending    = 0,
        rt_build_last = 0,
        rt_build_int  = 1, -- Rebuild routing tables every 5 seconds at minimum

        -- Load full routing table by default
        reload = ((conf.reload == false) and false) or true,
    }
    return setmetatable(o, {__index = Netlink})
end

function Netlink:transition(state)
    if state and state ~= self.state then
        print('Transitioning from state ' .. self.state .. ' to ' .. state)
        self.state = 'state_' .. state
    end
end

function Netlink:is_state(state)
    return self.state == 'state_' .. state
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
    local nh_idx_tab = self.nexthops_v4_idx
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

    local nh_idx = #nh_idx_tab + 1

	local gateway_wire = ipv4:pton(gateway)
	nh_idx_tab[nh_idx] = { nh = nh_details, intf = out_index, addr = gateway, direct = direct, addr_wire = gateway_wire }

    print('Adding ' .. prefix .. ' with gw ' .. gateway .. ' and NH index ' .. nh_idx)
    self.fib_v4:add_string(prefix, nh_idx)
    self.rt_pending = self.rt_pending + 1
end

function Netlink:del_route(nh_details)
    local nh_idx_tab = self.nexthops_v4_idx
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

	local gateway_wire = ipv4:pton(gateway)

    -- Todo: clean up unused next hops when routes are removed!
    self.fib_v4:remove_string(prefix)
    self.rt_pending = self.rt_pending + 1

    print('Route deleted ' .. prefix .. ' via ' .. gateway .. ' (' .. intf.phy_if .. ')')
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

    -- local ifs = self.interfaces
    -- -- If we have a configuration for this interface, then configure it!
    -- if ifs[msg.name] then
    --     local if_conf = ifs[msg.name]
    --     print('TODO: Configuring interface ' .. msg.name .. ' with ' .. tostring(if_conf.ip) .. '/' .. if_conf.prefix)
    --     --msg:address('1.2.3.4/32')
    -- end
end

function Netlink:maybe_build()
    -- Do not rebuild if no pending route updates
    if self.rt_pending < 1 then
        return
    end

    -- If last build was over rt_build_int ago
    local cur_now = now()
    if self.rt_build_last + self.rt_build_int < cur_now then
        print('Rebuilding routing tables with ' .. self.rt_pending .. ' pending routes...')
        self.fib_v4:build()
        local build_time = now() - cur_now
        print('Rebuild complete in ' .. (build_time * 1000 * 1000) .. ' ns')

        self.rt_build_last = cur_now
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
    if type(self[self.state]) == 'function' then
        fin_state = self[self.state](self)
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

