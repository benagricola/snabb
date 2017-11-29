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

local nf_index    = 2^16-1
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

    o.fib        = fib_mode:new()
    -- Add 'not found' route as LPM expects a default entry
    -- Index is converted to uint16_t so we use the maximum value
    -- for 'not found'
    o.fib:add_string('0.0.0.0/0', 0)

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
        key_type           = ffi_typeof('uint32_t'), -- IPv4 Address
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

function ForwarderChild:lookup_nexthop(dst)
    local nh_index = self.fib:search_bytes(dst)
    if nh_index == 0 or nh_index == nil then
        return nil, ERR_NO_ROUTE
    end

    -- If we're not a FIB master then only return results
    -- from cache. We learn cache items over interlink.
    if not self.next_hop_cache[nh_index] then
        print('Found route but no next-hop, FIX')
        return nil, ERR_NO_ROUTE
    end
    return self.next_hop_cache[nh_index]
end

-- Handle incoming transit (routable) packets
function ForwarderChild:push_transit(l_in, l_out)
    local interfaces = self.interfaces
    local l_in, l_out = self.input, self.output
    local l_master    = l_out['to_master']

    assert(l_master, 'App link to FIB master does not exist')

    for _, link_config in ipairs(self.interfaces) do
        local in_link   = l_in[link_config.phy_name]
        local ctrl_link = l_out[link_config.tap_name]

        if in_link then
            local p_count = l_nreadable(in_link)
            for _ = 1, p_count do
                local p = l_receive(in_link)
                local ether_hdr, arp_hdr, ip_hdr = rutil.parse(self, ctrl_link, link_config, p)

                -- If packet has no ethernet header, we cant read it!
                if not ether_hdr then
                    p_free(p)
                else
                    -- Found an ARP request. Forward to ctrl link. Clone and forward to master.
                    -- Master will flood back over interlink for processing
                    if arp_hdr then
                        local p_master = p_clone(p)
                        l_transmit(ctrl_link, p)
                        l_transmit(l_master, p_master)

                    elseif ip_hdr then

                        -- Forward control traffic directly.
                        if ip_hdr:dst_eq(link_config.ip) then
                            counter_add(shm.control)
                            l_transmit(ctrl_link, p)
                        else
                            local next_hop, err = self:lookup_nexthop(ip_hdr:dst())

                            -- If we found a next hop
                            if next_hop then
                                print('Route packet!')

                                p_free(p)
                                -- rutil.route(self, { ether_hdr = ether_hdr, ip_hdr = ip_hdr, link_config = link_config, p = p, dst = ip_hdr:dst()})
                            else
                                --print('[' .. self.id .. ']: Forwarding packet to master process')
                                l_transmit(l_master, p)
                            end
                        end
                    else
                        print('Child found non-arp, non-ip packet. Forwarding to ctrl')
                        l_transmit(ctrl_link, p)
                    end
                end
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
            local p = l_receive(link)
            local ether_hdr, arp_hdr, ip_hdr = rutil.parse(self, nil, nil, p)

            -- TODO: Check for routing update and parse

            -- Found an ARP request. Forward to master if necessary
            if arp_hdr then
                rutil.process_arp(self, arp_hdr)
                p_free(p)

            elseif ip_hdr then
                print('Child received IP packet over interlink. WAT DO?')
                p_free(p)
            end
        end
    end
end
