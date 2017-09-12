module(...,package.seeall)

local app    = require("core.app")
local pmu    = require("lib.pmu")
local packet = require("core.packet")
local p_free = packet.free

local now  = app.now

local cltable  = require("lib.cltable")

local bit  = require("bit")
local bit_rshift = bit.rshift

local lru  = require("lib.lru")
local lpm_ipv4 = require('lib.lpm.ip4')
local link = require("core.link")
local lib  = require("core.lib")
local counter = require("core.counter")
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local constants = require("apps.lwaftr.constants")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local math       = require('math')
local math_min   = math.min
local ffi        = require('ffi')

local counter_add = counter.add
local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

-- Constants
local ether_type_arp  = 0x0806
local ether_type_ipv4 = 0x0800
local ether_type_ipv6 = 0x86dd
local ether_header_len  = constants.ethernet_header_size



--- # `Route` app: Takes inbound packets on any input interface
--  # Resolves next-hop using specified 'FIB' app
--  # Forwards traffic to correct outbound interface, replacing necessary IP fields
Route = { }


function Route:new(conf)
    local o = {
        -- Only 1 FIB App since this is not int specific
        fib_app_name   = conf.fib_app or 'fib',
        fib_app        = nil,
        fib_cache_v4   = cltable.new({
		    key_type           = ffi.typeof('uint8_t[4]'), -- DST IPv4 Address
		    max_occupancy_rate = 0.4,
		    initial_size       = 100,
	    }),
        fib_cache_v6   = cltable.new({
		    key_type           = ffi.typeof('uint8_t[4]'), -- DST IPv4 Address
		    max_occupancy_rate = 0.4,
		    initial_size       = 100,
	    }),
        cache_age      = 5,

        -- Arp app is interface specific, name is passed through
        -- per-interface in 'interfaces'
        arp_apps   = {},
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
            dropped_invalid = {counter}
        }
    }

    -- Create ipairs-iterable list of interface names
    for int_name, vars in pairs(o.interfaces) do
        o.int_names[#o.int_names+1] = int_name
    end

    return setmetatable(o, { __index = Route })
end

function Route:get_nexthop(p, wire_ip)
    local shm = self.shm

    local fib_app = self.fib_app
    if not fib_app then
        fib_app = app.app_table[self.fib_app_name]
        self.fib_app = fib_app
        assert(self.fib_app, 'No valid FIB app available!')
    end

    local route = fib_app:resolve_nexthop(wire_ip)

	if not route then
		counter_add(shm.dropped_noroute)
		p_free(p)
		return
	end

	local interface = self.interfaces[route.intf]

    local arp_name = interface.arp_name

    local arp_apps = self.arp_apps

    if not arp_apps[arp_name] then
        local arp_instance = app.app_table[arp_name]
        assert(arp_instance, 'No valid ARP app for interface ' .. interface.phy_if .. ' available!')
        arp_apps[arp_name] = arp_instance
        self.arp_apps = arp_apps
    end

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
    local dst_mac = arp_apps[arp_name]:resolve_mac(next_ip)

	if not dst_mac then
		counter_add(shm.dropped_nomac)
		p_free(p)
		return
	end

    return { phy = interface.phy_name, ip = next_ip, src_mac = interface.mac, dst_mac = dst_mac, time = now() }
end


function Route:route(link_config, p)
    local shm = self.shm

    if p.length < ether_header_len then
       -- Packet too short.
       p_free(p)
       counter_add(shm.dropped_invalid)
       return
    end

    local ether_hdr = ethernet:new_from_mem(p.data, ether_header_len)

    if not ether_hdr then
        counter_add(shm.dropped_invalid)
        p_free(p)
        return
    end

    local ctrl_out = self.output[link_config.tap_name]

    local ether_type = ether_hdr:type()

    -- Forward ARP frames to control channel
    if ether_type == ether_type_arp then
		l_transmit(ctrl_out, p)
		counter_add(shm.arp)
		counter_add(shm.control)
        return
    end

    local ip_hdr

    -- Decode IPv4 as IPv4
    if ether_type == ether_type_ipv4 then
		ip_hdr = ipv4:new_from_mem(p.data + ether_header_len, p.length - ether_header_len)
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
        -- TODO: Send ICMP (11 - Time Exceeded)
        counter_add(shm.dropped_zerottl)
        p_free(p)
        return
    end

    local fib_cache_v4 = self.fib_cache_v4

    local cur_now = now()

    local ip_dst = ip_hdr:dst()

    local nh = fib_cache_v4[ip_dst]

    -- If cache entry is old, remove it
    -- TODO: Calculate expiry timer per-push rather than for every packet
    if nh and nh.time < (cur_now - self.cache_age) then
        nh = nil
    end

    if not nh then
        nh = self:get_nexthop(p, ip_dst)

        -- get_nexthop will free the packet and return on error
        -- so do not p_free() here!
        if not nh then
            return
        end

        fib_cache_v4[ip_dst] = nh

        print('Next hop resolved to interface ' .. nh.phy .. ' with GW address ' .. ipv4:ntop(nh.ip) .. ' and MAC addr ' .. ethernet:ntop(nh.dst_mac))
    end

    local l_out    = self.output
    local out_link = l_out[nh.phy]

    if not out_link then
        counter_add(shm.dropped_nophy)
        p_free(p)
        return
    end

    ether_hdr:src(nh.src_mac)
    ether_hdr:dst(nh.dst_mac)

    -- Set new TTL and modify the checksum
    ip_hdr:ttl(ip_hdr:ttl() - 1)

    -- Incrementally update checksum
    -- Subtracting 1 from the TTL involves *adding* 1 or 256 to the checksum - thanks ones complement
    -- sum = ipptr->Checksum + 0x100;  /* increment checksum high byte*/
    -- ipptr->Checksum = (sum + (sum>>16)) /* add carry */

	local h = ip_hdr:header()
	local sum = ntohs(h.checksum) + 0x100
	h.checksum = htons(sum + bit_rshift(sum, 16))

    -- TODO: MTU Check and discard (DF SET?) or fragment

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
