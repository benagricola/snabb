module(...,package.seeall)

-- Forwarder Child.
-- Does not handle FIB itself, but receives updates
-- from Master FIB and stores a local route cache with
-- resolved MAC addresses.

local app         = require('core.app')
local counter     = require('core.counter')
local datagram    = require('lib.protocol.datagram')
local ethernet    = require('lib.protocol.ethernet')
local ctable      = require('lib.ctable')

local packet      = require('core.packet')
local lpm_ipv4    = require('lib.lpm.ip4')
local lpm_trie    = require('lib.lpm.lpm4_trie')
local lpm_poptrie = require('lib.lpm.lpm4_poptrie')
local lpm_248     = require('lib.lpm.lpm4_248')
local lpm_dxr     = require('lib.lpm.lpm4_dxr')

local rutil       = require('apps.router.util')
local rtypes      = require('apps.router.types')
local netlink     = require('apps.socket.netlink').Netlink
local link        = require('core.link')

local ipv4        = require('lib.protocol.ipv4')

local S           = require('syscall')
local ffi         = require('ffi')
local ffi_typeof  = ffi.typeof

local C           = ffi.C

local pt          = S.types.pt


local nh_notfound_index = 2^15-1
local nh_drop_index     = nh_notfound_index - 1
local nh_max            = nh_drop_index - 1
local now               = app.now

local p_free, p_clone, p_resize, p_append = packet.free, packet.clone, packet.resize, packet.append
local l_transmit, l_receive, l_nreadable, l_nwriteable = link.transmit, link.receive, link.nreadable, link.nwriteable

local ERR_NO_ROUTE      = 1 -- Return network unreachable
local ERR_NO_MAC        = 2 -- Return network unreachable (no next-hop mac)
local ERR_NO_MAC_DIRECT = 3 -- Return host unreachable (no direct mac)

local fib_modes = {
    trie    = lpm_trie.LPM4_trie,
    poptrie = lpm_poptrie.LPM4_poptrie,
    ["248"] = lpm_248.LPM4_248,
    dxr     = lpm_dxr.LPM4_dxr
}
--- # `ForwarderChild` app subclasses netlink. Do NOT overwrite `config` or `shm` directly.
ForwarderChild = {
    config = {
        -- Which FIB (LPM) mode to use (trie, poptrie, 248, dxr available)
        fib_mode = { default  = 'dxr' },
        -- Interface Configuration Settings
        interfaces = { required = true },
        -- Used to identify this process in logs / stats etc
        id = { required = true },
    },
    shm = {
        control = { counter },
        data = { counter },
        arp = { counter },
        ipv4 = { counter },
        ipv6 = { counter },
        forwarded = { counter },
        dropped_noroute = { counter },
        dropped_nomac = { counter },
        dropped_nophy = { counter },
        dropped_zerottl = { counter },
        dropped_mtu = { counter },
        dropped_invalid = { counter }
    },
}


function ForwarderChild:new(conf)
    local o = {}

    o.id = conf.id

    local fib_mode = fib_modes[conf.fib_mode]
    assert(fib_mode, 'FIB Mode ' .. conf.fib_mode .. ' invalid.')

    o.fib        = fib_mode:new({ keybits = 15 })
    -- Add 'not found' route as LPM expects a default entry
    -- Index is converted to uint16_t so we use the maximum value
    -- for 'not found'
    o.fib:add_string('0.0.0.0/0', nh_notfound_index)

    o.interfaces = conf.interfaces

    -- This tracks macs of active hosts
    o.mac_table  = ctable.new({
        key_type           = ffi_typeof('uint8_t[4]'), -- IPv4 Address
        value_type         = rtypes.mac_v4_entry_t,
        max_occupancy_rate = 0.8,
        initial_size       = 100,
    })

    -- Next hops are cached by index and contain a resolved mac
    o.next_hop_cache = ctable.new({
        key_type           = ffi_typeof('uint16_t'),
        value_type         = rtypes.fib_v4_entry_t,
        max_occupancy_rate = 0.8,
        initial_size       = 100,
    })

    return setmetatable(o, { __index = ForwarderChild })
end

-- Handle input loop for slave
function ForwarderChild:push()
    local l_in     = self.input
    local l_out    = self.output

    -- Do work here!
    self:push_transit(l_in, l_out)
    self:push_interlink(l_in, l_out)
end

function ForwarderChild:lookup_nexthop_index(dst)
    local nh_index = self.fib:search_bytes(dst)

    if nh_index == nh_notfound_index then
        return nil, ERR_NO_ROUTE
    end

    return nh_index, nil

end

function ForwarderChild:lookup_nexthop_by_index(nh_idx)
    -- If we're not a FIB master then only return results
    -- from cache. We learn cache items over interlink.
    local nh = self.next_hop_cache:lookup_ptr(ffi_cast('uint16_t', nh_idx))
    assert(nh, 'Attempted to look up a next hop by index that does not exist!')
    return nh.value
end

-- Handle incoming transit (routable) packets
function ForwarderChild:push_transit(l_in, l_out)
    local interfaces = self.interfaces
    local l_in, l_out = self.input, self.output
    local l_master    = l_out['to_master']

    local shm = self.shm

    assert(l_master, 'App link to FIB master does not exist')

    for _, link_config in ipairs(self.interfaces) do
        local in_link   = l_in[link_config.phy_name]
        local ctrl_link = l_out[link_config.tap_name]

        if in_link then
            local p_count = l_nreadable(in_link)
            for _ = 1, p_count do
                repeat
                    local p = l_receive(in_link)
                    -- 1: Packet parsed by Forwarder Child

                    -- 2: Packet too short?
                    if rutil.q_packet_too_short(p) then
                       p_free(p)
                       counter_add(shm.dropped_invalid)
                       do break end
                    end

                    local ether_hdr = rutil.parse_ethernet_header(p)

                    -- 3: Ethernet header exists?
                    if not rutil.q_ethernet_header_exists(ether_hdr) then
                        counter_add(shm.dropped_invalid)
                        p_free(p)
                        do break end
                    end

                    -- 4: Is ARP?
                    if rutil.q_is_arp(ether_hdr) then
                        local p_master = p_clone(p)
                        l_transmit(ctrl_link, p)
                        l_transmit(l_master, p_master)
                        do break end
                    end

                    -- 5: Is IP (v4)?
                    if not rutil.q_is_ipv4(ether_hdr) then
                        counter_add(shm.ipv4)
                        l_transmit(ctrl_link, p)
                        do break end
                    end

                    local ip_hdr = rutil.parse_ipv4_header(self, p)
                    assert(ip_hdr, 'Unable to parse IPv4 header!')

                    -- 6: Is Control Traffic?
                    if rutil.q_is_control_traffic(ip_hdr, link_config) then
                        -- Forward control traffic directly.
                        counter_add(shm.control)
                        l_transmit(ctrl_link, p)
                        do break end
                    end

                    -- 7: Is TTL > 1?
                    if not rutil.q_is_ttl_gt_1(ip_hdr) then
                         -- TTL Exceeded in Transit
                         counter_add(shm.dropped_zerottl)
                         rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 11, 0)
                         do break end
                    end

                    -- Get index of next-hop stored in LPM
                    local nh_idx, err = self:lookup_nexthop_index(ip_hdr:dst())

                    -- 8: Cached next-hop exists?
                    if not nh_idx then
                        l_transmit(l_master, p)
                        do break end
                    end

                    -- 9: Cached next-hop specifies drop?
                    if nh_idx == nh_drop_index then
                         counter_add(shm.dropped_noroute)
                         rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 0)
                         do break end
                    end

                    -- Get actual next-hop struct
                    local next_hop = self:lookup_nexthop_by_index(nh_idx)

                    -- 10: Next-hop MAC Exists?
                    if not rutil.q_nh_mac_exists(next_hop) then
                        counter_add(shm.dropped_nomac)

                        -- 11: Is Route Direct?
                        if rutil.q_nh_is_direct(next_hop) then
                            rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 1)
                        else
                            rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 0)
                        end

                        do break end
                    end

                    -- Get output link
                    -- TODO: Preload out_link into self.interfaces
                    local out_int  = self.interfaces[next_hop.int_idx]
                    local out_link = l_out[out_int.phy_name]

                    assert(out_link, 'No outbound interface found for valid route!')

                    -- 12: Does packet require fragmenting?
                    if rutil.q_packet_needs_fragmenting(p, out_int.mtu) then
                        -- 13: Is DF bit set?
                        if rutil.q_is_df_set(ip_hdr) then
                            -- Destination Unreachable (Frag needed and DF set)
                            counter_add(shm.dropped_mtu)
                            rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 4, nil, out_int.mtu)
                        else
                            print('TODO: Packet needs fragmenting!')
                            p_free(p)
                        end
                        do break end
                    end

                    -- Packet does not need fragmenting

                    -- Rewrite ethernet src / dst
                    ether_hdr:src(out_int.mac)
                    ether_hdr:dst(next_hop.dst_mac)

                    -- Set new TTL. This automatically changes the checksum incrementally to match
                    ip_hdr:ttl_decr()

                    -- Transmit the packet
                    l_transmit(out_link, p)
                    counter_add(shm.forwarded)
                until true
            end
        end
    end
end


-- Handle incoming interlink (cross-process data) packets
-- These may contain route updates or ARP packets.
function ForwarderChild:push_interlink(l_in, l_out)
    local l_in, l_out = self.input, self.output
    local link = l_in['from_master']

    if link then
        local p_count = l_nreadable(link)
        for _ = 1, p_count do
            -- Parse route update here!

            local p = l_receive(link)
            print('Received interlink')
            p_free(p)
        end
    end
end
