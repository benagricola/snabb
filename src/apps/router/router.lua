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
local ethernet   = require('lib.protocol.ethernet')
local ipv4       = require('lib.protocol.ipv4')
local ipv6       = require('lib.protocol.ipv6')
local udp        = require('lib.protocol.udp')
local datagram   = require('lib.protocol.datagram')
local zebra      = require('lib.protocol.zebra')
local zm         = require('lib.zebra.message')
local zc         = require('lib.zebra.constants')
local ffi        = require('ffi')
local ffi_new    = ffi.new
local ffi_sizeof = ffi.sizeof
local ffi_copy   = ffi.copy

local transmit, receive, nreadable = link.transmit, link.receive, link.nreadable

local proto_udp = constants.proto_udp
local proto_tcp = constants.proto_tcp
local ethertype_ipv4 = constants.ethertype_ipv4

local e_hs     = ethernet:sizeof()
local v4_hs    = ipv4:sizeof()
local udp_hs   = udp:sizeof()
local zebra_hs = zebra:sizeof()

local function convert_ipv4(addr)
   if addr ~= nil then return ipv4:pton(ipv4_ntop(addr)) end
end

local function z_print(m)
    return print('ZAPIRouter: ' .. (m or 'nil'))
end

--- # `zAPIRouter` app: Route packets based on routing table learned via zAPI
zAPIRouterCtrl = {}


function zAPIRouterCtrl:new(conf)
    local o = {
        address     = conf.address or ipv4:pton('10.231.14.1'),
        interfaces  = conf.interfaces,
        port        = conf.port or 2600,
        vrf_id      = conf.vrf_id or 0,
        reply       = {},
        peer        = {},
    }

    -- Preconfigure Zebra header based on version. Ignore v0 because :care:
    o.zebra = {
        [1] = zebra:new({ vrf_id = self.vrf_id, version = 1 }),
        [2] = zebra:new({ vrf_id = self.vrf_id, version = 2 }),
        [3] = zebra:new({ vrf_id = self.vrf_id, version = 3 }),
    }

    return setmetatable(o, {__index=zAPIRouterCtrl})
end

function zAPIRouterCtrl:get_reply(payload, payload_len)
    -- Allocate a new packet and assign to datagram
    local p = packet.allocate()
    local dgram = datagram:new(p)

    -- Assign payload to packet
    dgram:payload(payload, payload_len)
    return dgram
end


function zAPIRouterCtrl:send(body)
    local lnk = self.output.ctrl

    -- Set zebra header version based on message body
    local zebra = self.zebra[body:version()]

    -- Set Zebra header command and length
    zebra:command(body:type())
    zebra:length(body:sizeof() + zebra:sizeof())

    -- Get header and body reply packets
    local r_header = self:get_reply(zebra:header_ptr(), zebra:sizeof())
    local r_body   = self:get_reply(body:data(), body:sizeof())

    transmit(lnk, r_header:packet())
    transmit(lnk, r_body:packet())
end

function zAPIRouterCtrl:send_interfaces(cmd, zmsg_opt)
    for index, int in ipairs(self.interfaces) do
	local p_zebra_interface = zm.ZebraInterface:new(zmsg_opt)
	p_zebra_interface:value('name', int.name)
	p_zebra_interface:value('index', index)
	p_zebra_interface:value('status', zc.INTERFACE_ACTIVE)
	p_zebra_interface:value('flags', 0)
	p_zebra_interface:value('metric', 1)
	p_zebra_interface:value('mtu_v4', 1500)
	p_zebra_interface:value('mtu_v6', 1500)
	p_zebra_interface:value('bandwidth', 1000)
	p_zebra_interface:value('llt', zc.LLT_ETHER)
	p_zebra_interface:value('hwaddr_len', ntohl(6))
	p_zebra_interface:value('hwaddr', int.mac)

	p_zebra_interface:type(cmd)
	self:send(p_zebra_interface)
    end
    return
end

local function process(self, p)
    local address    = self.address
    local interfaces = self.interfaces
    local port       = self.port

    local dgram = datagram:new(p)

    local p_zebra = dgram:parse_match(zebra)
    if not p_zebra then
        z_print('Unable to parse ZServ API packet')
        transmit(self.output.print, p)
        return nil
    end

    local cmd, version = p_zebra:command(), p_zebra:version()

    local zmsg_opt = { family = ethertype_ipv4, version = version }

    local body_mem, body_size = dgram:payload()

    local p_zebra_msg

    if cmd == zc.CMD_HELLO then
        p_zebra_msg = zm.ZebraHello:new_from_mem(body_mem, zmsg_opt)
	if not p_zebra_msg then
	    z_print('Unable to parse ZServ CMD_HELLO msg')
	    return true -- Free p
	end

        local route_type = p_zebra_msg:value('route_type')

        self.peer = { sending_route_type = route_type, receiving_route_type = nil, pending = true, version = version }
        z_print('Received HELLO from peer with route type ' .. zc.ROUTE[route_type] .. ' and version ' .. version)

        local p_zebra_id_add = zm.ZebraRouterID:new(zmsg_opt)
        p_zebra_id_add:value('family', 2)
        p_zebra_id_add:value('prefix', self.address)
        p_zebra_id_add:value('prefixlen', 32)
        p_zebra_id_add:type(zc.CMD_ROUTER_ID_UPDATE)

        self:send(p_zebra_id_add)

        -- Send our interfaces
        self:send_interfaces(zc.CMD_INTERFACE_ADD, zmsg_opt)

	return true -- Free p
    end

    local peer = self.peer

    if cmd == zc.CMD_ROUTER_ID_ADD then
        -- Reply with our own ROUTER_ID_ADD
        z_print('Received ROUTER_ID_ADD from peer - setting active and replying with ROUTER_ID_UPDATE...')
        peer.pending = false
	return true -- Free p
    end

    if cmd == zc.CMD_INTERFACE_ADD then
        -- Client may have no interfaces
        if body_size == 0 then
            z_print('Peer has with no interfaces...')
	    return true -- Free p
        end

        p_zebra_msg = zm.ZebraInterface:new_from_mem(body_mem, zmsg_opt)
	if not p_zebra_msg then
	    z_print('Unable to decode Zebra INTERFACE_ADD')
	    return true -- Free p
        else
            z_print('Received INTERFACE_ADD: ' .. p_zebra_msg:value('name'))
            transmit(self.output.print, p)
            return nil
	end
        return true -- Free p
    end

    if cmd == zc.CMD_REDISTRIBUTE_ADD then
        p_zebra_msg = zm.ZebraRedistribute:new_from_mem(body_mem, zmsg_opt)
	if not p_zebra_msg then
	    z_print('Unable to parse ZServ CMD_REDISTRIBUTE_ADD msg')
            transmit(self.output.print, p)
	    return nil
	end
        local route_type = p_zebra_msg:value('route_type')
        z_print('Peer is asking us to send routes of type ' .. zc.ROUTE[route_type])
        peer.receiving_route_type = route_type
        return true -- Free p
    end

    return true -- Free p if no command matched
end

function zAPIRouterCtrl:push()
    local lnk       = self.input.ctrl
    local readable  = nreadable(lnk)

    -- Process packets on control interfaces
    for _ = 1, readable do
        -- Receive packet
        local p = receive(lnk)
        local status = process(self, p)
        if status then
            packet.free(p)
        end
    end
end

