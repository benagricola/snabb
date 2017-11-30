-- Contains utility functionality - routing, packet parsing etc
-- To keep the main forwarding modules smaller

local app         = require('core.app')
local ethernet    = require('lib.protocol.ethernet')
local arp         = require('lib.protocol.arp')

local rtypes      = require('apps.router.types')
local link        = require('core.link')
local packet      = require('core.packet')
local counter     = require('core.counter')

local math        = require('math')
local icmp        = require('lib.protocol.icmp.header')

local ipv4        = require('lib.protocol.ipv4')

local S           = require('syscall')
local ffi         = require('ffi')
local ffi_cast    = ffi.cast
local ffi_copy    = ffi.copy
local ffi_fill    = ffi.fill
local ffi_new     = ffi.new
local ffi_typeof  = ffi.typeof

local C           = ffi.C

local pt          = S.types.pt

local now          = app.now
local counter_add  = counter.add
local math_min     = math.min

local p_free, p_clone, p_resize, p_append = packet.free, packet.clone, packet.resize, packet.append
local l_transmit, l_receive, l_nreadable, l_nwriteable = link.transmit, link.receive, link.nreadable, link.nwriteable

-- Constants
local valid_ethertypes = {
    [0x0800] = true, -- IPv4
    [0x0806] = true, -- ARP
    [0x86DD] = true  -- IPv6
}

local e_hdr_len    = ethernet:sizeof()
local a_hdr_len    = arp:sizeof()
local ip_hdr_len   = ipv4:sizeof()
local icmp_hdr_len = icmp:sizeof()

local ether_type_arp     = 0x0806
local ether_type_ipv4    = 0x0800
local ether_type_ipv6    = 0x86dd
local arp_oper_request   = 1
local arp_oper_reply     = 2
local arp_htype_ethernet = 1
local arp_ptype_ipv4     = 0x0800
local arp_hlen_ethernet  = 6
local arp_plen_ipv4      = 4
local ip_proto_icmp      = 1
local ip_ttl_default     = 64
local ip_df_mask         = 0x4000

local icmp_reply_body_offset = e_hdr_len + ip_hdr_len + icmp_hdr_len + 4
local icmp_reply_unused1_offset = icmp_reply_body_offset - 4
local icmp_reply_unused2_offset = icmp_reply_body_offset - 2

local ether_offset = e_hdr_len
local ip_offset    = ether_offset + ip_hdr_len
local icmp_offset  = ip_offset + icmp_hdr_len

local ethernet_header_ptr_type = rtypes.ethernet_header_ptr_type
local ipv4_header_ptr_type     = rtypes.ipv4_header_ptr_type
local arp_header_ptr_type      = rtypes.arp_header_ptr_type

local mac_unknown = ethernet:pton("00:00:00:00:00:00")
local mac_broadcast = ethernet:pton("ff:ff:ff:ff:ff:ff")

local ERR_NO_ROUTE      = 1 -- Return network unreachable
local ERR_NO_MAC        = 2 -- Return network unreachable (no next-hop mac)
local ERR_NO_MAC_DIRECT = 3 -- Return host unreachable (no direct mac)

local route_direct_bit = 0x80000000


local _M = {}

-- Create ARP packet with template fields set
function _M.make_arp_request_tpl(src_mac, src_ipv4)
    local pkt  = packet.allocate()
    pkt.length = ethernet:sizeof() + arp:sizeof()

    local ethernet_hdr = ethernet:new_from_mem(pkt.data, e_hdr_len)
    local arp_hdr      = arp:new_from_mem(pkt.data + e_hdr_len, a_hdr_len)

    ethernet_hdr:dst(mac_broadcast)
    ethernet_hdr:src(src_mac)
    ethernet_hdr:type(ether_type_arp)

    arp_hdr:htype(arp_htype_ethernet)
    arp_hdr:ptype(arp_ptype_ipv4)
    arp_hdr:oper(arp_oper_request)
    arp_hdr:sha(src_mac)
    arp_hdr:spa(src_ipv4)
    arp_hdr:tha(mac_unknown)
    return arp_hdr, pkt
end


-- 2: Packet too short?
function _M.q_packet_too_short(p)
    return p.length < e_hdr_len
end

-- 3: Ethernet header exists? (checks against valid type)
function _M.q_ethernet_header_exists(ether_hdr)
    local ethertype = tonumber(ether_hdr:type())
    return valid_ethertypes[ethertype]
end

-- 4: Is Arp?
function _M.q_is_arp(ether_hdr)
    return ether_hdr:type() == ether_type_arp
end

-- 5: Is IP (v4)?
function _M.q_is_ipv4(ether_hdr)
    return ether_hdr:type() == ether_type_ipv4
end

-- 6: Is Control Traffic?
function _M.q_is_control_traffic(ip_hdr, link_config)
    return ip_hdr:dst_eq(link_config.ip)
end

-- 7: Is TTL > 1?
function _M.q_is_ttl_gt_1(ip_hdr)
    return ip_hdr:ttl() <= 1
end

-- 10: Next-hop MAC Exists?
function _M.q_nh_mac_exists(next_hop)
    return next_hop.mac ~= mac_unknown
end

-- 11: Is Route Direct
function _M.q_nh_mac_exists(next_hop)
    return next_hop.direct == 1
end

-- 12: Does packet require fragmenting?
function _M.q_packet_needs_fragmenting(p, mtu)
    -- If packet length minus ether header is bigger than the outbound MTU
    return (p.length - e_hdr_len) > mtu
end

-- 13: Is DF bit set?
function _M.q_is_df_set(ip_hdr)
    -- Then Check the DF bit. If set, drop, otherwise fragment
    return  bit_band(ip_hdr:flags(), ip_df_mask)
end

function _M.parse_ethernet_header(p)
    return ffi_cast(ethernet_header_ptr_type, p.data, e_hdr_len)
end

function _M.parse_arp_header(p)
    return ffi_cast(arp_header_ptr_type, p.data + e_hdr_len, a_hdr_len)
end

function _M.parse_ipv4_header(p)
    return ffi_cast(ipv4_header_ptr_type, p.data + e_hdr_len, p.length - e_hdr_len)
end

function _M.send_icmp_reply(self, p, eth_hdr, ip_hdr, link_config, typ, code, unused_1, unused_2)
    local shm = self.shm
    local src_ip, dst_if = link_config.ip, link_config.phy_name

    -- Turn existing IP packet p into ICMP packet!
    -- Copies existing IP header + data forwards,
    -- and initialises icmp header in the gap.

    local data_len = math_min(ip_hdr:total_length(), ip_hdr_len + 8)

    -- Minimum packet size is 56 (56 - 20 - 4) = 32
    if data_len < 32 then
        data_len = 32
    end

    -- Resize packet
    p.length = icmp_reply_body_offset + data_len

    -- Copy payload data (from IP header onwards) to end of packet
    ffi_copy(p.data + icmp_reply_body_offset, p.data + e_hdr_len, data_len)

    -- Allow 'unused fields' (default 4 zeroed bytes) to be set to 16bit vars
    if unused_1 then
        ffi_cast(uint16_ptr_t, p.data + icmp_reply_unused1_offset )[0] = htons(unused_1)
    else
        ffi_fill(p.data + icmp_reply_unused1_offset, 2)
    end

    if unused_2 then
        ffi_cast(uint16_ptr_t, p.data + icmp_reply_unused2_offset )[0] = htons(unused_2)
    else
        ffi_fill(p.data + icmp_reply_unused2_offset, 2)
    end

    -- Initialise ICMP header in place
    local icmp_hdr = icmp:new_from_mem(p.data + ip_offset, icmp_hdr_len)

    -- Default to ICMP Echo Reply
    icmp_hdr:type(typ or 0)
    icmp_hdr:code(code or 0)

    -- Flip src and dst mac addr
    eth_hdr:swap()

    ip_hdr:protocol(ip_proto_icmp)
    ip_hdr:ttl(ip_ttl_default)
    ip_hdr:dst(ip_hdr:src())
    ip_hdr:src(src_ip)

    icmp_hdr:checksum(p.data + icmp_offset, p.length - icmp_offset)
    ip_hdr:total_length(data_len + icmp_hdr_len + ip_hdr_len + 4)

    -- Have to fully calculate the checksum
    ip_hdr:checksum()

    -- Modified packet is routed as-normal
    local out_link = self.output[dst_if]
    if not out_link then
        counter_add(shm.dropped_nophy)
        p_free(p)
        return
    end

    l_transmit(out_link, p)
    return true
end

function _M.resolve_mac(self, phy, ip)
    local mac_entry = self.mac_table:lookup_ptr(ip)
    local mac
    local output = self.output[phy]
    local ap = self.arp_packet[phy]

    assert(ap, 'No ARP request template found for phy ' .. phy)

    if mac_entry then
        mac = mac_entry.value
        -- If mac is still valid then just return
        if mac.expires > now() then
            return mac.mac
        end

        -- If mac has expired then send arp request, but return existing mac
        _M.send_arp_request(self, output, ap, ip)

        return mac.mac
    end

    -- If no mac entry exists, then no mac was stored. Return as much.
    _M.send_arp_request(self, output, ap, ip)
    return nil
end

function _M.send_arp_request(self, output, ap, dst_ip)
    if not output then return nil end
    local arp_hdr, p = unpack(ap)

    -- Set IP we're asking for
    arp_hdr:tpa(dst_ip)
    l_transmit(output, p_clone(p))
end

function _M.process_arp(self, arp_hdr)
    -- Abort if not an ARP reply
    if arp_hdr:oper() ~= arp_oper_reply then
        return
    end

    -- Abort if not Ethernet + IPv4 ARP
    if arp_hdr:htype() ~= arp_htype_ethernet or
    arp_hdr:ptype() ~= arp_ptype_ipv4 or
     arp_hdr:hlen() ~= 6 or arp_hdr:plen() ~= 4 then
        return false
    end

    local ip  = arp_hdr:spa()
    local mac = arp_hdr:sha()

    print(("Route: Resolved '%s' to %s"):format(ipv4:ntop(ip), ethernet:ntop(mac)))

    _M.save_mac(self, ip, mac)
end

function _M.save_mac(self, ip, mac)
    local mac_entry = rtypes.mac_v4_entry_t({ ip = ip, mac = mac, expires = now() + self.arp_request_interval })
    print('Saving mac ' .. ethernet:ntop(mac) .. ' with IP ' .. ipv4:ntop(ip))
    self.mac_table:add(ip, mac_entry, true)
end

function _M.route(self, item, nh)
    local shm = self.shm
    local ether_hdr, ip_hdr, link_config, p =
        item.ether_hdr, item.ip_hdr, item.link_config, item.p

    -- Select correct interface or drop if not managed
    local int      = self.interfaces[nh.int_idx]
    local l_out    = self.output
    local out_link = l_out[int.phy_name]

    if not out_link then
        counter_add(shm.dropped_nophy)
        p_free(p)
        return
    end

    -- If packet length minus ether header is bigger than the outbound MTU
    -- We need to know the output link to decide what the MTU is
    -- Once we know the MTU, we need to return the packet out of the received
    -- port.
    local mtu = int.mtu

    if (p.length - e_hdr_len) > mtu then
        -- Then Check the DF bit. If set, drop packet. Send reply
        if bit_band(ip_hdr:flags(), ip_df_mask) then
            counter_add(shm.dropped_mtu)

            -- Destination Unreachable (Frag needed and DF set)
            return _M.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 4, nil, mtu)
        else
            print('Packet length exceeds outbound link MTU but DF not set, fragging...')
            -- TODO: Actually fragment packet
        end
    end

    -- Rewrite ethernet src / dst
    ether_hdr:src(nh.src_mac)
    ether_hdr:dst(nh.dst_mac)

    -- Set new TTL. This automatically changes the checksum incrementally to match
    ip_hdr:ttl_decr()

    -- Transmit the packet
    l_transmit(out_link, p)
    counter_add(shm.forwarded)
end

function _M.send_err(self, ether_hdr, ip_hdr, link_config, p, err)
    if err == ERR_NO_ROUTE or err == ERR_NO_MAC then
	-- Network Unreachable
	_M.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 0)
	return
    elseif err == ERR_NO_MAC_DIRECT then
	-- Host Unreachable
	_M.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 1)
        return
    end

    p_free(p)
    return
end

return _M
