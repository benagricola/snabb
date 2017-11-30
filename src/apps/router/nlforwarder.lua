module(...,package.seeall)

-- Netlink Forwarder. Loads and listens for routes from
-- Linux Netlink. Resolves next-hops and forwards traffic.
-- Multi-process safe with a single parent (core FIB) app
-- and multiple child apps.
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
local ffi_new     = ffi.new
local ffi_cast    = ffi.cast

local C           = ffi.C

local pt          = S.types.pt

local nh_notfound_index = 2^15-1
local nh_drop_index     = nh_notfound_index - 1
local nh_max            = nh_drop_index - 1

local now         = app.now

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
--- # `NLForwarder` app subclasses netlink. Do NOT overwrite `config` or `shm` directly.
NLForwarder = setmetatable({}, { __index = netlink })

-- Which FIB (LPM) mode to use (trie, poptrie, 248, dxr available)
NLForwarder.config.fib_mode = { default  = 'dxr' }

-- Interface Configuration Settings
NLForwarder.config.interfaces = { required = true }

local counters = { 'control', 'data', 'arp', 'ipv4', 'ipv6', 'forwarded', 'dropped_noroute', 'dropped_nomac', 'dropped_nophy', 'dropped_zerottl', 'dropped_mtu', 'dropped_invalid' }
for _, cname in ipairs(counters) do
    NLForwarder.shm[cname] = { counter }
end

function NLForwarder:new(conf)
    local o = netlink.new(self, conf)

    local fib_mode = fib_modes[conf.fib_mode]
    assert(fib_mode, 'FIB Mode ' .. conf.fib_mode .. ' invalid.')

    o.fib        = fib_mode:new({ keybits = 15 })
    -- Add 'not found' route as LPM expects a default entry
    -- Index is converted to uint16_t so we use the maximum value
    -- for 'not found'
    o.fib:add_string('0.0.0.0/0', nh_notfound_index)

    o.interfaces = conf.interfaces
    o.load_fib   = true

    -- This tracks macs of active hosts
    o.mac_table  = ctable.new({
        key_type           = ffi_typeof('uint8_t[4]'), -- IPv4 Address
        value_type         = rtypes.mac_v4_entry_t,
        max_occupancy_rate = 0.8,
        initial_size       = 100,
    })

    o.tap_map    = {}
    o.arp_packet = {}

    -- This is populated as netlink links are added
    o.linux_map = {}

    o.arp_request_interval = 10

    -- This is populated as next-hops are generated
    -- next_hop_idx is a sparse array of gateway IPs
    -- in integer format, while next_hops holds each
    -- next hop keyed by index. Direct next-hop always
    -- exists here since it's handled differently.
    -- This tracks macs of active hosts
    o.next_hop_idx  = ctable.new({
        key_type           = ffi_typeof('uint16_t'), -- Next hop Index is maximum 65535
        value_type         = rtypes.fib_v4_entry_t,
        max_occupancy_rate = 0.8,
        initial_size       = 10,
    })
    o.next_hop_map  = ctable.new({
        key_type           = ffi_typeof('uint32_t'), -- Next hop Index is gateway IP in numeric format
        value_type         = ffi_typeof('uint16_t'),
        max_occupancy_rate = 0.8,
        initial_size       = 10,
    })

    -- Tracks number of next hops stored in next_hop_idx
    o.next_hop_ctr = 0

    return setmetatable(o, { __index = NLForwarder })
end

-- Generate link tables
function NLForwarder:link ()
    -- Generate TAP map
    for idx, interface in ipairs(self.interfaces) do
        self.tap_map[interface.tap_if] = idx
        self.arp_packet[interface.phy_name] = { rutil.make_arp_request_tpl(interface.mac, interface.ip) }
    end
end

function NLForwarder:push()
    local l_in     = self.input
    local l_out    = self.output

    -- Do work here!
    self:push_interlink(l_in, l_out)
    -- If master, read netlink and maybe load fib
    self:maybe_load_fib()
end


function NLForwarder:maybe_load_fib(l_out)
    if self.load_fib then
        self:request_interfaces()
        self:request_routes()
        self.load_fib = false
    end
end

function NLForwarder:lookup_nexthop_index(dst)
    local nh_index = self.fib:search_bytes(dst)

    if nh_index == nh_notfound_index then
        return nil, ERR_NO_ROUTE
    end

    return nh_index, nil
end

function NLForwarder:lookup_nexthop_by_index(nh_idx)
    -- If we're not a FIB master then only return results
    -- from cache. We learn cache items over interlink.
    local nh = self.next_hop_cache:lookup_ptr(ffi_cast('uint16_t', nh_idx))
    assert(nh, 'Attempted to look up a next hop by index that does not exist!')
    return nh.value
end


-- Handle incoming interlink (cross-process data) packets
-- These may contain route updates or ARP packets.
function NLForwarder:push_interlink(l_in, l_out)
    local interfaces  = self.interfaces
    local l_in, l_out = self.input, self.output
    local l_master    = l_out['to_master']
    local in_link     = l_in['from_children']

    local shm = self.shm

    if in_link then
        local p_count = l_nreadable(in_link)
        for _ = 1, p_count do
            repeat
                local p = l_receive(in_link)
                -- 14: Packet parsed by Forwarder Master
                -- If packet has got here, sanity checks were already performed
                -- by child - so we can happily skip them

                local ether_hdr = rutil.parse_ethernet_header(p)
                assert(ether_hdr, 'Forwarder Master received invalid packet')

                -- 15: Is ARP?
                if rutil.q_is_arp(ether_hdr) then
                    local arp_hdr = rutil.parse_arp_header(p)
                    print('TODO: Update next-hop table')
                    p_free(p)
                    do break end
                end

                assert(rutil.q_is_ipv4(ether_hdr), 'Forwarder Master received non-IP / non-ARP packet')

                local ip_hdr = rutil.parse_ipv4_header(self, p)
                assert(ip_hdr, 'Unable to parse IPv4 header!')

                -- Get index of next-hop stored in LPM
                local nh_idx, err = self:lookup_nexthop_index(ip_hdr:dst())

                -- 16: Next-hop exists?
                if not nh_idx or nh_idx == nh_drop_index then
                    -- Flood drop update to Forwarder Children
                    print('TODO: Flood drop update to children')
                    rutil.send_icmp_reply(self, p, ether_hdr, ip_hdr, link_config, 3, 0)
                    do break end
                end

                -- Get actual next-hop struct
                local next_hop = self:lookup_nexthop_by_index(nh_idx)

                -- 17: Next-hop MAC Exists?
                if not rutil.q_nh_mac_exists(next_hop) then
                    counter_add(shm.dropped_nomac)

                    print('TODO: Flood no-mac update to children')

                    -- 18: Is Route Direct?
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
function NLForwarder:push_interlink(l_in, l_out)
    local master      = self.master
    local l_in, l_out = self.input, self.output
    local link_child  = l_out['to_children']

    local link = l_in['from_children']

    if link then
        local p_count = l_nreadable(link)
        for _ = 1, p_count do

            local p = l_receive(link)
            print('Received packet from child on interlink')
            local ether_hdr, arp_hdr, ip_hdr = rutil.parse(self, nil, nil, p)
            if not ether_hdr then
                p_free(p)
            else
                if arp_hdr then
                    -- Process ARP packet and flood to children
                    rutil.process_arp(self, arp_hdr)
                    l_transmit(link_child, p)

                elseif ip_hdr then
                    local next_hop, err = self:lookup_nexthop(ip_hdr:dst())

                    if next_hop then
                        print('Master found route for packet, forwarding and flooding route update...')
                    else
                        print('Master did not find route for packet due to err ' .. tostring(err) .. ', dropping...')
                        p_free(p)
                    end
                end
            end
        end
    end
end


function NLForwarder:on_new_route(msg)
    local next_hop_idx = self.next_hop_idx
    local next_hop_map = self.next_hop_map

    local prefix = tostring(msg.dest) .. '/' .. tostring(msg.dst_len)
    local gw     = tostring(msg.gw)

    -- Resolve outbound interface by mapping linux index to local index
    local out_idx = self.linux_map[tonumber(msg.index)]

    -- If route is not for one of our mapped interfaces, ignore...
    if not out_idx then
        return
    end

    -- Get outbound interface from local index
    local out_if = self.interfaces[out_idx]

    if not out_if then
        print('Unable to resolve outbound interface for route ' .. tostring(msg))
        return
    end

    -- Turn gateway into number
    local gw_int = lpm_ipv4.parse(gw)

    -- Next-hop is direct if no gateway specified
    local direct = (gw_int == 0)

    local nh_idx = next_hop_map:lookup_ptr(gw_int)

    -- If we have no NH idx stored for this gateway then create
    if not nh_idx then

        -- Pregenerate next-hop wire address
        local gateway_wire = ipv4:pton(gw)

        local fib_entry = rtypes.fib_v4_entry_t({
            expires  = 0,
            direct   = tonumber(direct),
            int_idx  = out_idx,
            next_ip  = gateway_wire,
            src_mac  = out_if.mac,
            dst_mac  = {0,0,0,0,0,0},
            refcount = 1
        })

        self.next_hop_ctr = self.next_hop_ctr + 1
        nh_idx = self.next_hop_ctr

        next_hop_idx:add(nh_idx, fib_entry)
        next_hop_map:add(gw_int, nh_idx)
        self.fib:add_string(prefix, nh_idx)

        print('Adding ' .. prefix .. ' with new gateway ' .. gw .. ' and NH index ' .. tonumber(nh_idx))
    else
        local nh = next_hop_idx:lookup_ptr(nh_idx.value)
        assert(nh, 'No next hop found but exists in gateway index')
        nh.value.refcount = tonumber(nh.value.refcount) + 1
        print('Adding ' .. prefix .. ' with existing gateway ' .. gw .. ', NH index ' .. tonumber(nh_idx.value) .. ' and refcount ' .. nh.value.refcount)
        self.fib:add_string(prefix, nh_idx.value)
    end

    self.fib:build()
end


function NLForwarder:on_del_route(msg)
    local next_hop_idx = self.next_hop_idx
    local next_hop_map = self.next_hop_map

    local prefix = tostring(msg.dest) .. '/' .. tostring(msg.dst_len)
    local gw     = tostring(msg.gw)

    -- Turn gateway into number
    local gw_int = lpm_ipv4.parse(gw)

    -- Next-hop is direct if no gateway specified
    local direct = (gw_int == 0)

    local nh_idx = next_hop_map:lookup_ptr(gw_int)

    if not nh_idx then
        print('Route deleted that we were not aware of, ignoring...')
        return
    end

    local nh = next_hop_idx:lookup_ptr(nh_idx.value)

    assert(nh, 'Unable to find next-hop entry for valid gateway next-hop')

    print('Deleting ' .. prefix .. ' with gateway ' .. gw .. ', NH index ' .. (tonumber(nh_idx.value)) .. ' and refcount ' .. nh.value.refcount)

    self.fib:remove_string(prefix)
    self.fib:build()

    nh.value.refcount = tonumber(nh.value.refcount) - 1

    -- NEVER delete direct route next-hop as this is a special case
    if nh.value.refcount < 1 and not direct then
        print('Next-hop index ' .. tonumber(nh_idx.value) .. ' no longer in use, deleting...')
        next_hop_idx:remove(nh_idx.value)
        next_hop_map:remove(gw_int)
        self.next_hop_ctr = self.next_hop_ctr - 1
    end
end


-- On new link, configure interface and save index map
function NLForwarder:on_new_link(msg)
    local ifname  = msg.name
    local tap_idx = tonumber(msg.ifinfo.ifi_index)
    local phy_idx = self.tap_map[ifname]
    local ifcfg   = self.interfaces[phy_idx]

    if self.linux_map[tap_idx] then
        return
    end

    if not phy_idx then
        print('Ignoring new link ' .. ifname .. ' which we are not configured to manage...')
        return
    end

    if not ifcfg then
        print('Unable to find physical interface for TAP device ' .. ifname)
        return
    end

    print('New interface ' .. ifname .. ' index mapping is ' .. phy_idx .. ':' .. tap_idx .. ' (Snabb:Linux)')

    self.linux_map[tap_idx] = tonumber(phy_idx)

    msg:address(tostring(ipv4:ntop(ifcfg.ip)) .. '/' .. tostring(ifcfg.prefix))
    msg:setmtu(ifcfg.mtu)
    msg:setmac(ethernet:ntop(ifcfg.mac))
end


function NLForwarder:on_del_link(msg)
    local ifname  = msg.name
    local tap_idx = msg.ifinfo.ifi_index
    local phy_idx = self.tap_map[ifname]
    local ifcfg   = self.interfaces[phy_idx]

    if not phy_idx then
        print('Ignoring deleted link ' .. ifname .. ' which we are not configured to manage...')
        return
    end

    if not ifcfg then
        print('Unable to find physical interface for TAP device ' .. ifname)
        return
    end
    print('Deleted interface ' .. ifname .. ' index mapping is ' .. phy_idx .. ':' .. tap_idx .. ' (Snabb:Linux)')

    self.linux_map[tap_idx] = nil
end
