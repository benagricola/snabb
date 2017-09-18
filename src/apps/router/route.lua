module(...,package.seeall)

local app       = require("core.app")
local arp       = require("lib.protocol.arp")
local bit       = require("bit")
local ctable    = require("lib.ctable")
local constants = require("apps.lwaftr.constants")
local counter   = require("core.counter")
local datagram  = require("lib.protocol.datagram")
local ethernet  = require("lib.protocol.ethernet")
local ffi       = require("ffi")
local icmp      = require("lib.protocol.icmp.header")
local ipv4      = require("lib.protocol.ipv4")
local ipv6      = require("lib.protocol.ipv6")
local lib       = require("core.lib")
local link      = require("core.link")
local lpm_ipv4  = require("lib.lpm.ip4")
local lru       = require("lib.lru")
local math      = require("math")
local packet    = require("core.packet")
local pmu       = require("lib.pmu")

local bit_band     = bit.band
local bit_rshift   = bit.rshift
local counter_add  = counter.add
local ffi_cast     = ffi.cast
local ffi_copy     = ffi.copy
local ffi_fill     = ffi.fill
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local math_min     = math.min
local now          = app.now
local uint16_ptr_t = ffi_typeof("uint16_t*")

local p_free, p_clone, p_resize, p_append = packet.free, packet.clone, packet.resize, packet.append
local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

-- Constants
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


local mac_unknown = ethernet:pton("00:00:00:00:00:00")
local mac_broadcast = ethernet:pton("ff:ff:ff:ff:ff:ff")

local fib_v4_entry_t = ffi_typeof([[
   struct {
      uint8_t  next_ip[4];
      uint8_t  src_mac[6];
      uint8_t  dst_mac[6];
      uint32_t expires;
      uint32_t int_idx;
   }
]])

local mac_v4_entry_t = ffi_typeof([[
   struct {
      uint8_t  ip[4];
      uint8_t  mac[6];
      uint32_t expires;
   }
]])


local function copy_len(src, len)
   local dst = ffi_new('uint8_t['..len..']')
   ffi_copy(dst, src, len)
   return dst
end


-- Create ARP packet with template fields set
local function make_arp_request_tpl(src_mac, src_ipv4)
    local pkt  = packet.allocate()
    pkt.length = ethernet:sizeof() + arp:sizeof()

    src_mac  = copy_len(src_mac, 6)
    src_ipv4 = copy_len(src_ipv4, 4)

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

--- # `Route` app: Takes inbound packets on any input interface
--  # Resolves next-hop using specified 'FIB' app
--  # Forwards traffic to correct outbound interface, replacing necessary IP fields
Route = { }


function Route:new(conf)
    local o = {
        -- Only 1 FIB App since this is not int specific
        fib_app_name = conf.fib_app or 'fib',
        fib_app      = nil,

        fib_cache_v4 = ctable.new({
            key_type           = ffi_typeof('uint8_t[4]'), -- IPv4 Address
            value_type         = fib_v4_entry_t,
            max_occupancy_rate = 0.8,
            initial_size       = 1024,
        }),

        mac_table     = ctable.new({
            key_type           = ffi_typeof('uint8_t[4]'), -- IPv4 Address
            value_type         = mac_v4_entry_t,
            max_occupancy_rate = 0.8,
            initial_size       = 256,
        }),

        cache_age    = 15,
        arp_packet   = {},
        arp_request_interval = 30,

        interfaces = conf.interfaces or {},
        int_names  = {},
        shm = {
            control         = {counter},
            data            = {counter},
            arp             = {counter},
            ipv4            = {counter},
            ipv6            = {counter},
            forwarded       = {counter},
            dropped_noroute = {counter},
            dropped_nomac   = {counter},
            dropped_nophy   = {counter},
            dropped_zerottl = {counter},
            dropped_mtu     = {counter},
            dropped_invalid = {counter}
        }
    }

    -- Create ipairs-iterable list of interface names
    -- Also create ARP request template for each interface
    for int_name, vars in pairs(o.interfaces) do
        o.int_names[#o.int_names+1] = int_name
        o.arp_packet[vars.phy_name] = { make_arp_request_tpl(vars.mac, vars.ip) }
    end

    return setmetatable(o, { __index = Route })
end


function Route:send_icmp_reply(p, eth_hdr, ip_hdr, link_config, typ, code, unused_1, unused_2)
    local shm = self.shm
    local src_ip, dst_if = link_config.ip, link_config.phy_name

    -- Turn existing IP packet p into ICMP packet!
    -- Copies existing IP header + data forwards,
    -- and initialises icmp header in the gap.
    local data_len = math_min(ip_hdr:total_length(), ip_hdr_len+12)

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

    eth_hdr:swap()
    ip_hdr:protocol(ip_proto_icmp)
    ip_hdr:ttl(ip_ttl_default)
    ip_hdr:dst(ip_hdr:src())
    ip_hdr:src(src_ip)

    icmp_hdr:checksum(p.data + icmp_offset, data_len)
    ip_hdr:total_length(data_len + icmp_hdr_len + ip_hdr_len)

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


function Route:save_mac(ip, mac)
    local mac_entry = mac_v4_entry_t({ mac = mac, expires = now() + self.arp_request_interval })
    print('Saving mac ' .. ethernet:ntop(mac) .. ' with IP ' .. ipv4:ntop(ip))
    self.mac_table:add(ip, mac_entry, true)
end


function Route:resolve_mac(phy, ip)
    local mac_entry = self.mac_table:lookup_ptr(ip)
    local mac
    local output = self.output[phy]

    if mac_entry then
        mac = mac_entry.value
        -- If mac is still valid then just return
        if mac.expires > now() then
            return mac.mac
        end

        -- If mac has expired then send arp request, but return existing mac
        self:send_arp_request(phy, ip)

        return mac.mac
    end

    -- If no mac entry exists, then no mac was stored. Return as much.
    self:send_arp_request(phy, ip)
    return nil
end


function Route:send_arp_request(phy, dst_ip)
    local output = self.output[phy]

    if not output then return nil end

    local ap = self.arp_packet[phy]

    if not ap then
        print('No ARP request template found for phy ' ..phy)
        return
    end

    local arp_hdr, p = unpack(ap)

    -- Set IP we're asking for
    arp_hdr:tpa(copy_len(dst_ip, 4))
    l_transmit(output, p_clone(p))
end


function Route:process_arp(phy, arp_hdr)
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

    local ip  = copy_len(arp_hdr:spa(), 4)
    local mac = copy_len(arp_hdr:sha(), 6)

    print(("Route: Resolved '%s' to %s on %s"):format(ipv4:ntop(ip), ethernet:ntop(mac), phy))

    self:save_mac(ip, mac)
end


function Route:get_nexthop(wire_ip)
    local cur_now = now()

    local shm = self.shm
    local fib_cache_v4 = self.fib_cache_v4

    local nh_ptr = fib_cache_v4:lookup_ptr(wire_ip)
    local nh

    -- If route is valid, return
    if nh_ptr then
        nh = nh_ptr.value
        if nh.expires > cur_now then
            return nh
        end
    end

    local fib_app = self.fib_app
    if not fib_app then
        fib_app = app.app_table[self.fib_app_name]
        self.fib_app = fib_app
        assert(self.fib_app, 'No valid FIB app available!')
    end

    local route = fib_app:resolve_nexthop(wire_ip)

    if not route then
        counter_add(shm.dropped_noroute)
        return
    end

    local interface = self.interfaces[route.intf]

    local next_ip

    -- If directly connected, don't look up next-hop since there is none
    -- Look up mac of given wire_ip and use that instead
    if route.direct then
        next_ip = wire_ip
    else
        next_ip = route.addr_wire
    end

    -- Now we have the next hop interface and gateway address
    -- We need to look up any existing arp cache entry from the arp handler (which snoops on arp replies)
    -- ARP handler should automatically generate an ARP request if no cache entry exists
    local dst_mac = self:resolve_mac(interface.phy_name, next_ip)

    if not dst_mac then
        print('Unable to resolve ' .. ipv4:ntop(next_ip) .. ' to MAC')
        counter_add(shm.dropped_nomac)
        return
    end

    local route_expires_in = cur_now + self.cache_age

    -- Update existing FIB entry
    if nh then
        nh.next_ip = next_ip
        nh.src_mac = interface.mac
        nh.dst_mac = dst_mac
        nh.int_idx = route.intf
        nh.expires = route_expires_in

    -- Create new FIB entry
    else
        nh = fib_v4_entry_t({
            next_ip = next_ip,
            src_mac = interface.mac,
            dst_mac = dst_mac,
            int_idx = route.intf,
            expires = route_expires_in
        })
    end

    print('Next hop resolved to interface ' .. nh.int_idx .. ' with GW address ' .. ipv4:ntop(nh.next_ip) .. ' and MAC addr ' .. ethernet:ntop(nh.dst_mac) .. ' expiring in ' .. math.floor((nh.expires - now())) .. ' seconds')

    -- Add to cache
    fib_cache_v4:add(wire_ip, nh, true)
    return nh
end


function Route:route(link_config, p)
    local shm = self.shm

    if p.length < e_hdr_len then
       -- Packet too short.
       p_free(p)
       counter_add(shm.dropped_invalid)
       return
    end

    local ether_hdr = ethernet:new_from_mem(p.data, e_hdr_len)

    if not ether_hdr then
        counter_add(shm.dropped_invalid)
        p_free(p)
        return
    end

    local ctrl_out = self.output[link_config.tap_name]

    local ether_type = ether_hdr:type()

    -- Forward ARP frames to control channel
    if ether_type == ether_type_arp then
        local arp_hdr = arp:new_from_mem(p.data + e_hdr_len, a_hdr_len)
        self:process_arp(link_config.phy_name, arp_hdr)
        l_transmit(ctrl_out, p)
        counter_add(shm.arp)
        counter_add(shm.control)
        return
    end

    local ip_hdr

    -- Decode IPv4 as IPv4
    if ether_type == ether_type_ipv4 then
        ip_hdr = ipv4:new_from_mem(p.data + e_hdr_len, p.length - e_hdr_len)
        counter_add(shm.ipv4)

    -- Decode IPv6 as IPv6
    elseif ether_type == ether_type_ipv6 then
        -- TODO: Implement IPv6 processing
        counter_add(shm.ipv6)
        counter_add(shm.dropped_invalid)
        p_free(p)
        return
    end

    -- Drop unknown layer3 traffic
    if not ip_hdr then
        counter_add(shm.dropped_invalid)
        p_free(p)
        return
    end

    -- Forward control traffic directly as Linux will do all of the checking below itself.
    if ip_hdr:dst_eq(link_config.ip) then
        counter_add(shm.control)
        l_transmit(ctrl_out, p)
        return
    end

    -- Validate TTL or reply with an error
    if ip_hdr:ttl() <= 1 then
        -- Turn existing packet into ICMP reply packet
        counter_add(shm.dropped_zerottl)
        return self:send_icmp_reply(p, ether_hdr, ip_hdr, link_config, 11, 0)
    end

    -- Get packet next hop, cached
    local ip_dst = ip_hdr:dst()
    local nh = self:get_nexthop(ip_dst)

    -- If no next hop, drop packet
    if not nh then
        print('Unable to resolve next-hop IP or MAC, dropping...')
        p_free(p)
        return
    end

    -- Select correct interface or drop if not managed
    local int = self.interfaces[nh.int_idx]
    local l_out    = self.output
    local out_link = l_out[int.phy_name]

    if not out_link then
        counter_add(shm.dropped_nophy)
        p_free(p)
        return
    end

    -- If packet length minus ether header is bigger than the outbound MTU
    -- TODO: Clean this up to avoid code repetition
    -- TODO: Send outbound ICMP via inbound port without route lookup
    -- We need to know the output link to decide what the MTU is
    -- Once we know the MTU, we need to return the packet out of the received
    -- port.

    if (p.length - e_hdr_len) > int.mtu then
        -- Then Check the DF bit. If set, drop packet. Send reply
        if bit_band(ip_hdr:flags(), ip_df_mask) then
            counter_add(shm.dropped_zerottl)

            -- Set MTU in ICMP reply packet
            return self:send_icmp_reply(p, ether_hdr, ip_hdr, link_config, 3, 4, nil, int.mtu)
        else
            print('Packet length exceeds outbound link MTU but DF not set, fragging...')
            -- TODO: Actually fragment packet
        end
    end

    -- Rewrite ethernet src / dst
    ether_hdr:src(nh.src_mac)
    ether_hdr:dst(nh.dst_mac)

    -- Set new TTL.
    ip_hdr:ttl(ip_hdr:ttl() - 1)

    -- Incrementally update checksum
    -- Subtracting 1 from the TTL involves *adding* 1 or 256 to the checksum - thanks ones complement
    -- TODO: May need further rshift for larger packets?
    local h = ip_hdr:header()
    local sum = ntohs(h.checksum) + 0x100
    h.checksum = htons(sum + bit_rshift(sum, 16))

    -- Transmit the packet
    l_transmit(out_link, p)
    counter_add(shm.forwarded)
end

-- Handle input packets
function Route:push()
    -- Iterate over input links
    local i_names  = self.int_names
    local i_config = self.interfaces
    local l_in     = self.input

    -- Iterate over interface names and resolve to link
    for _, link_name in ipairs(i_names) do
        local in_link = l_in[link_name]
        if in_link then
            local p_count = l_nreadable(in_link)
            for _ = 1, p_count do
                local p = l_receive(in_link)
                self:route(i_config[link_name], p)
            end
        end
    end
end
