module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local link = require("core.link")
local lib  = require("core.lib")
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local constants = require("apps.lwaftr.constants")
local lwutil = require("apps.lwaftr.lwutil")
local rd16, wr16, rd32, wr32 = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.wr32
local is_ipv4, is_ipv6 = lwutil.is_ipv4, lwutil.is_ipv6
local ipv4_ntop  = require("lib.yang.util").ipv4_ntop
local ethernet = require('lib.protocol.ethernet')
local ipv4     = require('lib.protocol.ipv4')
local udp      = require('lib.protocol.udp')
local datagram = require('lib.protocol.datagram')
local zserv    = require('lib.protocol.zserv')
local ffi      = require('ffi')
local ffi_new  = ffi.new

local transmit, receive, nreadable = link.transmit, link.receive, link.nreadable

local zserv_marker  = 255
local zserv_version = 2

local proto_udp = constants.proto_udp
local proto_tcp = constants.proto_tcp

local zserv_commands = {
    'INTERFACE_ADD',
    'INTERFACE_DELETE',
    'INTERFACE_ADDRESS_ADD',
    'INTERFACE_ADDRESS_DELETE',
    'INTERFACE_UP',
    'INTERFACE_DOWN',
    'IPV4_ROUTE_ADD',
    'IPV4_ROUTE_DELETE',
    'IPV6_ROUTE_ADD',
    'IPV6_ROUTE_DELETE',
    'REDISTRIBUTE_ADD',
    'REDISTRIBUTE_DELETE',
    'REDISTRIBUTE_DEFAULT_ADD',
    'REDISTRIBUTE_DEFAULT_DELETE',
    'IPV4_NEXTHOP_LOOKUP',
    'IPV6_NEXTHOP_LOOKUP',
    'IPV4_IMPORT_LOOKUP',
    'IPV6_IMPORT_LOOKUP',
    'INTERFACE_RENAME',
    'ROUTER_ID_ADD',
    'ROUTER_ID_DELETE',
    'ROUTER_ID_UPDATE',
    'HELLO',
    'IPV4_NEXTHOP_LOOKUP_MRIB',
    'VRF_UNREGISTER',
    'INTERFACE_LINK_PARAMS',
    'NEXTHOP_REGISTER',
    'NEXTHOP_UNREGISTER',
    'NEXTHOP_UPDATE',
    'MESSAGE_MAX',
}

for int, var in ipairs(zserv_commands) do
    zserv_commands[var] = int
end

-- Valid state transitions - 1 entry per valid state.
-- First item is name of state, second item is list of states to transition to (ok, fail)
local state_transitions = {
    {'INIT', 'WAIT_HELLO'},
    {'WAIT_HELLO', 'REPLY_HELLO'},
    {'REPLY_HELLO', { 'WAIT_CMD', 'INIT' }},
    {'WAIT_CMD', { 'REPLY_CMD', 'INIT' }},
    {'REPLY_CMD', { 'WAIT_CMD', 'INIT' }},
}

local states = {}

local transitions = {}

for int, var in ipairs(state_transitions) do
    local state_name, valid_transitions = var[1], var[2]

    states[state_name] = int
    states[int]        = state_name

    local transit
    if type(valid_transitions) == 'table' then
        transit = { ok = valid_transitions[1], fail = valid_transitions[2] }
    else
    	transit = { ok = valid_transitions, fail = valid_transitions }
    end

    transitions[state_name] = transit
    transitions[int] = transit
end


local e_hs     = ethernet:sizeof()
local v4_hs    = ipv4:sizeof()
local udp_hs   = udp:sizeof()
local zserv_hs = zserv:sizeof()

--- # `zAPIRouter` app: Route packets based on routing table learned via zAPI

zAPIRouterCtrl = {}


function zAPIRouterCtrl:new(conf)
    local o = {
        address     = conf.address or ipv4:pton('10.231.14.1'),
        port        = conf.port or 2600,
        state       = states.INIT,
    }

    o._match_addr = function(p_ipv4)
	return p_ipv4:dst_eq(o.address)
    end

    o._cache = {
        p = ffi_new("struct packet *[1]"),
        mem = ffi_new("uint8_t *[1]")
    }

    return setmetatable(o, {__index=zAPIRouterCtrl})
end

function zAPIRouterCtrl:transition(result, if_state)
    local if_state = if_state or self.state

    if self.state ~= if_state then
	return false
    end

    local result = result or 'ok'
    for k, v in pairs(transitions) do
        print(k,v)
    end
    for k, v in ipairs(transitions) do
        print(k,v)
    end

    local valid_transitions = transitions[self.state]
    local new_state = states[valid_transitions[result]]

    if not new_state then
	print('[zAPIRouterCtrl] invalid transition from ' .. self.state)
	return false
    end

    if self.state == new_state then
	return false
    end

    print('zAPIRouterCtrl transition ' .. states[self.state] .. ' -> ' .. states[new_state])
    self.state = new_state
    return new_state
end

-- length;
-- marker;
-- version;
-- vrf_id;
-- command;
function zAPIRouterCtrl:reply(dst_ip, dst_port, command, options,  body)
    local options = options or {}
    local p = packet.allocate()
    local dgram = datagram:new(p)
    local p_zreply = zserv:new({ vrf_id = options['vrf_id'], command = command })
    dgram:push(p_zreply)

    local p_udpreply = udp:new({ src_port = self.port, dst_port = dst_port })

end

function zAPIRouterCtrl:process()
    local addresses = self.addresses
    local port      = self.port

    local lnk  = self.input.ctrl

    local readable  = nreadable(lnk)

    -- Process packets on control interfaces
    for _ = 1, readable do
        -- Receive packet
        local p = receive(lnk)
        if is_ipv4(p) then
            local offset, length = e_hs, p.length - e_hs

            local p_ipv4 = ipv4:new_from_mem(p.data + offset, length)
            local p_ipv4_dst = rd32(p_ipv4:dst())

            -- Packet must be destined for known address
            if self.addresses[p_ipv4_dst] then
                if p_ipv4:protocol() == proto_udp then
                    offset, length = (offset + v4_hs), (length - v4_hs)

                    local p_udp = udp:new_from_mem(p.data + offset, length)

                    -- Validate incoming port
                    if p_udp:dst_port() == port then
                        offset, length = (offset + udp_hs), (length - udp_hs)

                        local p_zserv = zserv:new_from_mem(p.data + offset, length)

                        -- Validate zserv msg for known marker and version
                        if p_zserv:marker() == zserv_marker then
                            if p_zserv:version() == zserv_version then
                                -- Extract command
				local cmd = p_zserv:command()

                                if cmd == zserv_commands.HELLO then
                                    print('Received Hello, replying...')
                                    local reply_ip   = p_ipv4:src()
                                    local reply_port = p_udp:src_port()
                                    self:reply(reply_ip, reply_port, zserv_commands.HELLO, { }, nil)
                                    self:reply(reply_ip, reply_port, zserv_commands.ROUTER_ID_ADD, { }, nil)
                                else
                                    local cmd_name = zserv_commands[cmd]
				    print('Received unknown / unhandled command ID ' .. cmd .. ' ' .. (cmd_name or 'Unknown'))
                                end
                            else
                                print('Received invalid zserv API version ' .. p_zserv:version())
                            end
                        else
                            print('Received invalid marker value ' .. p_zserv:marker())
                        end
                    end
                end
            end
        end

        packet.free(p)
    end
end

function zAPIRouterCtrl:push()
    self:transition(nil, states['INIT'])
    self:process()
end

