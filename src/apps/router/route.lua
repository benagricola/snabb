module(...,package.seeall)

local app    = require("core.app")
local packet = require("core.packet")
local p_free = packet.free

local link = require("core.link")
local lib  = require("core.lib")
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local constants = require("apps.lwaftr.constants")
local lwutil = require("apps.lwaftr.lwutil")
local rd16, wr16, rd32, wr32 = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.wr32
local is_ipv4, is_ipv6 = lwutil.is_ipv4, lwutil.is_ipv6
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local math       = require('math')
local math_min   = math.min
local ffi        = require('ffi')
local ffi_new    = ffi.new
local ffi_sizeof = ffi.sizeof
local ffi_copy   = ffi.copy

local ethertype_arp = 0x0806

local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

--- # `Route` app: Takes inbound packets on any input interface
--  # Resolves next-hop using specified 'FIB' app
--  # Forwards traffic to correct outbound interface, replacing necessary IP fields
Route = { }


function Route:new(conf)
    local o = {
        -- Only 1 FIB App since this is not int specific
        fib_app_name = conf.fib_app or 'fib',
        fib_app  = nil,
        -- Arp app is interface specific, name is passed through
        -- per-interface in 'interfaces'
        arp_apps = {},
        interfaces = conf.interfaces or {},
    }

    return setmetatable(o, { __index = Route })
end

function Route:get_nexthop_ip(wire_ip)
    local fib_app = self.fib_app
    if not fib_app then
        fib_app = app.app_table[self.fib_app_name]
        self.fib_app = fib_app
        assert(self.fib_app, 'No valid FIB app available!')
    end

    return fib_app:resolve_nexthop(wire_ip)
end

function Route:get_nexthop_mac(interface, wire_ip_nexthop)
    local arp_apps = self.arp_apps
    local arp_name = interface.arp_name

    if not arp_apps[arp_name] then
        local arp_instance = app.app_table[arp_name]
        assert(arp_instance, 'No valid ARP app for interface ' .. interface.phy_if .. ' available!')
        arp_apps[arp_name] = arp_instance
        self.arp_apps = arp_apps
    end

    return arp_apps[arp_name]:resolve_mac(wire_ip_nexthop)
end

function Route:route(p)
    local ether_hdr = ethernet:new_from_mem(p.data, constants.ethernet_header_size)

    if not is_ipv4(p) then
        p_free(p)
        return
    end

    local ip_hdr = ipv4:new_from_mem(p.data + constants.ethernet_header_size, p.length - constants.ethernet_header_size)

    -- Lookup route
    local route = self:get_nexthop_ip(ip_hdr:dst())

    if not route then
        print('No route found')
        p_free(p)
        return
    end

    local interface = self.interfaces[route.intf]

    -- If directly connected, don't look up next-hop since there is none -
    local next_ip

    -- Look up mac of ipv4:dst() and use that instead
    if route.direct then
        next_ip = ip_hdr:dst()
    else
        next_ip = route.addr_wire
    end

    -- Now we have the next hop interface and gateway address
    -- We need to look up any existing arp cache entry from the arp handler (which snoops on arp replies)
    local dst_mac = self:get_nexthop_mac(interface, route.addr_wire)

    if not dst_mac then
        print('Unable to resolve next-hop IP ' .. route.addr .. ' to MAC address!')
        p_free(p)
        return
    end

    print('Next hop resolved to interface ' .. interface.phy_if .. ' with GW address ' .. route.addr .. ' and MAC addr ' .. ethernet:ntop(dst_mac))
    -- If we have no existing arp cache, we ask the arp handler to submit an  arp request for the gateway IP.
    -- If we have an arp cache entry, rewrite the packet, forward it to the output interface. Routing done.

    ether_hdr:src(interface.mac)
    ether_hdr:dst(dst_mac)

    local out_link = self.output[interface.phy_name]

    if not out_link then
        print('Unable to find output link for interface ' .. interface.phy_name)
        p_free(p)
    end

    l_transmit(out_link, p)
end

-- Handle input packets
function Route:push()
    -- Input and output links
    local l_in = self.input
    local l_out = self.output

    for link_name, link in pairs(l_in) do
        local p_count = l_nreadable(link)
        for _ = 1, p_count do
            local p = l_receive(link)
            self:route(p)
        end
    end
end
