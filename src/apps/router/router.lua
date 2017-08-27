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
        peers       = {},
    }

    -- Preconfigure Zebra header based on version. Ignore v0 because :care:
    o.zebra = {
        [1] = zebra:new({ vrf_id = self.vrf_id, version = 1 }),
        [2] = zebra:new({ vrf_id = self.vrf_id, version = 2 }),
        [3] = zebra:new({ vrf_id = self.vrf_id, version = 3 }),
    }

    return setmetatable(o, {__index=zAPIRouterCtrl})
end

function zAPIRouterCtrl:get_reply(dst_ip, dst_port, payload, payload_len)
    local k = ipv4:ntop(dst_ip) .. dst_port

    -- Generate new packet headers where required (dst ip / port changes)
    if not self.reply[k] then
        self.reply[k] = {
            eth     = ethernet:new({ type = ethertype_ipv4 }),
            ipv4    = ipv4:new({ src = self.address, dst = dst_ip, protocol = proto_udp, ttl = 64, flags = 0x02 }),
            udp     = udp:new({ src_port = self.port, dst_port = dst_port }),
        }
    end

    local r = self.reply[k]

    -- Allocate a new packet and assign to datagram
    local p = packet.allocate()
    local dgram = datagram:new(p)

    -- Packet length starts with length of payload
    local len = payload_len

    -- Assign payload to packet
    dgram:payload(payload, len)

    -- Calculate UDP length + checksum, and push
    len = len + r.udp:sizeof()
    r.udp:length(len)
    r.udp:checksum(p.data, p.length, r.ipv4)

    dgram:push(r.udp)

    -- Calculate IP length + checksum, and push
    len = len + r.ipv4:sizeof()
    r.ipv4:total_length(len)
    r.ipv4:checksum()
    dgram:push(r.ipv4)

    -- Push Ethernet
    dgram:push(r.eth)
    return dgram
end


function zAPIRouterCtrl:send(dst_ip, dst_port, body)
    local lnk = self.output.ctrl

    -- Set zebra header version based on message body
    local zebra = self.zebra[body:version()]

    -- Set Zebra header command and length
    zebra:command(body:type())
    zebra:length(body:sizeof() + zebra:sizeof())

    -- Get header and body reply packets
    local r_header = self:get_reply(dst_ip, dst_port, zebra:header_ptr(), zebra:sizeof())
    local r_body   = self:get_reply(dst_ip, dst_port, body:data(), body:sizeof())

    transmit(lnk, r_header:packet())
    transmit(lnk, r_body:packet())
end

local function get_peer(self, peer)
    local peer_settings = self.peers[peer]

    if not peer_settings then
	z_print('Received command from unknown peer ' .. peer .. ', did it send a HELLO? ')
        return nil
    end

    return peer_settings
end

local function process(self, p)
    local address    = self.address
    local interfaces = self.interfaces
    local port       = self.port

    local dgram = datagram:new(p, ethernet)
    -- Parse the ethernet, ipvx amd udp headers
    dgram:parse_n(3)

    local stack = dgram:stack()
    local p_eth, p_ipvx, p_udp = unpack(stack)

    if not p_ipvx:dst_eq(address) then
        z_print('Packet dst address not equal to local addr')
        return nil
    end

    local src_ip, src_port, dst_ip, dst_port =
        p_ipvx:src(), p_udp:src_port(), p_ipvx:dst(), p_udp:dst_port()

    local peer = ipv4:ntop(src_ip)

    if dst_port ~= port then
        z_print('Packet dst port not equal to local port')
        return nil
    end

    -- Valid packet, decode zAPI
    local p_zebra = dgram:parse_match(zebra)
    if not p_zebra then
        z_print('Unable to parse ZServ API packet')
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
	    return nil
	end

        local route_type = p_zebra_msg:value('route_type')

        self.peers[peer] = { sending_route_type = route_type, receiving_route_type = nil, pending = true, version = version }
        z_print('Received HELLO from peer ' .. peer .. ' with route type ' .. zc.ROUTE[route_type] .. ' and version ' .. version)

        local p_zebra_id_add = zm.ZebraRouterID:new(zmsg_opt)
        p_zebra_id_add:value('family', 2)
        p_zebra_id_add:value('prefix', p_ipvx:src())
        p_zebra_id_add:value('prefixlen', 32)
        p_zebra_id_add:type(zc.CMD_ROUTER_ID_UPDATE)

        self:send(src_ip, src_port, p_zebra_id_add)
        return
    end

    -- Check for valid peer settings for all further commands
    local peer_settings = get_peer(self, peer)

    if not peer_settings then
	return
    end

    if cmd == zc.CMD_ROUTER_ID_ADD then
        -- Reply with our own ROUTER_ID_ADD
        z_print('Received ROUTER_ID_ADD from peer ' .. peer .. ' - setting active and replying with ROUTER_ID_UPDATE...')
        peer_settings.pending = false
        return
    end

    if cmd == zc.CMD_INTERFACE_ADD then
        -- Client may have no interfaces
        if body_size == 0 then
            z_print('Received INTERFACE_ADD from peer ' .. peer .. ' - with no interfaces...')
            for index, int in ipairs(self.interfaces) do
	        local p_zebra_interface_add = zm.ZebraInterface:new(zmsg_opt)
                p_zebra_interface_add:value('name', int.name)
                p_zebra_interface_add:value('index', index)
                p_zebra_interface_add:value('status', zc.INTERFACE_ACTIVE)
                p_zebra_interface_add:value('flags', 0)
                p_zebra_interface_add:value('metric', 1)
                p_zebra_interface_add:value('mtu_v4', 1500)
                p_zebra_interface_add:value('mtu_v6', 1500)
                p_zebra_interface_add:value('bandwidth', 1000)
                p_zebra_interface_add:value('llt', zc.LLT_ETHER)
                p_zebra_interface_add:value('hwaddr_len', ntohl(6))

		p_zebra_interface_add:type(zc.CMD_INTERFACE_ADD)

		self:send(src_ip, src_port, p_zebra_interface_add)
            end
            return
        end

        p_zebra_msg = zm.ZebraInterface:new_from_mem(body_mem, zmsg_opt)
	if not p_zebra_msg then
	    z_print('Unable to decode Zebra INTERFACE_ADD')
	    return nil
	end
        return
    end

    if cmd == zc.CMD_REDISTRIBUTE_ADD then
        p_zebra_msg = zm.ZebraRedistribute:new_from_mem(body_mem, zmsg_opt)
	if not p_zebra_msg then
	    z_print('Unable to parse ZServ CMD_REDISTRIBUTE_ADD msg')
	    return nil
	end
        local route_type = p_zebra_msg:value('route_type')
        z_print('Peer ' .. peer .. ' is asking us to send routes of type ' .. zc.ROUTE[route_type])
        peer_settings.receiving_route_type = route_type
        return
    end
end

function zAPIRouterCtrl:push()
    local lnk       = self.input.ctrl
    local readable  = nreadable(lnk)

    -- Process packets on control interfaces
    for _ = 1, readable do
        -- Receive packet
        local p = receive(lnk)
        print('Received ctrl packet')
        local status = process(self, p)
        packet.free(p)
    end
end

