module(...,package.seeall)

-- Netlink Forwarder. Loads and listens for routes from
-- Linux Netlink. Resolves next-hops and forwards traffic.
-- Multi-process safe with a single parent (core FIB) app
-- and multiple child apps.
local app         = require("core.app")
local counter     = require("core.counter")
local datagram    = require("lib.protocol.datagram")
local ethernet    = require("lib.protocol.ethernet")

local lpm_ipv4    = require('lib.lpm.ip4')
local lpm_trie    = require('lib.lpm.lpm4_trie')
local lpm_poptrie = require('lib.lpm.lpm4_poptrie')
local lpm_248     = require('lib.lpm.lpm4_248')
local lpm_dxr     = require('lib.lpm.lpm4_dxr')

local rtypes      = require("apps.router.types")
local netlink     = require("apps.socket.netlink").Netlink
local link        = require("core.link")
local packet      = require("core.packet")

local ipv4        = require("lib.protocol.ipv4")

local S           = require("syscall")
local ffi         = require("ffi")
local ffi_typeof  = ffi.typeof

local C           = ffi.C

local pt          = S.types.pt

local now          = app.now

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

local fib_v4_entry_t = ffi_typeof([[
   struct {
      uint32_t expires;
      uint32_t int_idx;
      uint8_t  next_ip[4];
      uint8_t  direct;
      uint8_t  src_mac[6];
      uint8_t  dst_mac[6];
   }
]])

local mac_v4_entry_t = ffi_typeof([[
   struct {
      uint8_t  ip[4];
      uint32_t expires;
      uint8_t  mac[6];
   }
]])

--- # `NLForwarder` app subclasses netlink. Do NOT overwrite `config` or `shm` directly.
NLForwarder = setmetatable({}, { __index = netlink })

-- Is this process the master?
NLForwarder.config.master   = { default  = false }

-- Which FIB (LPM) mode to use (trie, poptrie, 248, dxr available)
NLForwarder.config.fib_mode = { default  = 'dxr' }

-- Interface Configuration Settings
NLForwarder.config.interfaces = { required = true  }

local counters = { 'control', 'data', 'arp', 'ipv4', 'ipv6', 'forwarded', 'dropped_noroute', 'dropped_nomac', 'dropped_nophy', 'dropped_zerottl', 'dropped_mtu', 'dropped_invalid' }
for _, cname in ipairs(counters) do
    NLForwarder.shm[cname] = { counter }
end

function NLForwarder:new(conf)
    local o = netlink.new(self, conf)

    local fib_mode = fib_modes[conf.fib_mode]
    assert(fib_mode, 'FIB Mode ' .. conf.fib_mode .. ' invalid.')

    o.fib        = fib_mode:new()
    o.fib:add_string('0.0.0.0/0', -1)
    o.master     = conf.master
    o.interfaces = conf.interfaces
    o.load_fib   = true

    local tap_map = {}

    -- Generate TAP map
    for idx, interface in ipairs(conf.interfaces) do
        tap_map[interface.tap_if] = idx
    end

    o.tap_map   = tap_map

    -- This is populated as netlink links are added
    o.linux_map = {}

    -- This is populated as next-hops are generated
    -- next_hop_idx is a sparse array of gateway IPs
    -- in integer format, while next_hops holds each
    -- next hop keyed by index. Direct next-hop always
    -- exists here since it's handled differently.
    o.next_hop_idx = { [1] = { direct = true, refcount = 0 }}
    o.next_hop_map = { [0] = 1 }

    if conf.master then
        o.push = NLForwarder.push_master
    else
        o.pull = nil
        o.push = NLForwarder.push_slave
    end

    return setmetatable(o, { __index = NLForwarder })
end


-- Handle input loop for slave
function NLForwarder:push_slave()
    local l_in     = self.input
    local l_out    = self.output

    -- Do work here!
    self:push_transit(l_in, l_out)
    self:push_interlink(l_in, l_out)
end


function NLForwarder:push_master()
    local l_in     = self.input
    local l_out    = self.output

    -- Do work here!
    self:push_transit(l_in, l_out)
    self:push_interlink(l_in, l_out)

    -- If master, read netlink and maybe load fib
    self:maybe_load_fib()
end


function NLForwarder:maybe_load_fib(l_out)
    if self.load_fib then
        self:request_interfaces()
        --self:request_routes()
        self.load_fib = false
    end
end


-- Handle incoming transit (routable) packets
function NLForwarder:push_transit(l_in, l_out)
    return true
end


-- Handle incoming interlink (cross-process data) packets
function NLForwarder:push_interlink(l_in, l_out)
    return true
end

-- Handle incoming netlink (routing update) packets, if master
function NLForwarder:push_netlink(l_in, l_out)
    if not self.master then return end
end


function NLForwarder:on_new_route(msg)
    local next_hop_map = self.next_hop_map
    local next_hop_idx = self.next_hop_idx

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

    -- Turn gateway numeric
    local gw_int = lpm_ipv4.parse(gw)

    -- Next-hop is direct if no gateway specified
    local direct = (gw_int == 0)

    -- Get next-hop from gateway integer
    local nh_idx = next_hop_map[gw_int]

    -- If next hop doesn't exist, create it
    if not nh_idx then
        nh_idx = #next_hop_idx + 1
        next_hop_map[gw_int] = nh_idx

        -- Pregenerate next-hop wire address
        local gateway_wire = ipv4:pton(gw)
        next_hop_idx[nh_idx] = {
            nh       = msg,
            out_idx  = out_idx,
            addr     = gateway_wire,
            direct   = false,
            refcount = 1,
        }
    else
        next_hop_idx[nh_idx].refcount = next_hop_idx[nh_idx].refcount + 1
    end

    print('Adding ' .. prefix .. ' with gateway ' .. gw .. ' and NH index ' .. nh_idx)
    self.fib:add_string(prefix, nh_idx)
    self.fib:build()
end


function NLForwarder:on_del_route(msg)
    local next_hop_map = self.next_hop_map
    local next_hop_idx = self.next_hop_idx

    local prefix = tostring(msg.dest) .. '/' .. tostring(msg.dst_len)
    local gw     = tostring(msg.gw)

    -- Turn gateway numeric
    local gw_int = lpm_ipv4.parse(gw)

    -- Next-hop is direct if no gateway specified
    local direct = (gw_int == 0)

    -- Get next-hop from gateway integer
    local nh_idx = next_hop_map[gw_int]


    print('Deleting ' .. prefix .. ' with gateway ' .. gw .. ' and NH index ' .. (nh_idx or 'none'))
    self.fib:remove_string(prefix)
    self.fib:build()

    if nh_idx then
	local refcount = next_hop_idx[nh_idx].refcount - 1

	-- NEVER delete direct route next-hop as this is a special case
	if refcount < 1 and not direct then
	    next_hop_map[gw_int] = nil
	    next_hop_idx[nh_idx] = nil
	    print('Next-hop index ' .. nh_idx .. ' no longer in use, deleting...')
	else
	    next_hop_idx[nh_idx].refcount = refcount
	end
    end
end


-- On new link, configure interface and save index map
function NLForwarder:on_new_link(msg)
    local ifname  = msg.name
    local tap_idx = msg.ifinfo.ifi_index
    local phy_idx = self.tap_map[ifname]
    local ifcfg   = self.interfaces[phy_idx]

    if not phy_idx then
        print('Ignoring new link ' .. ifname .. ' which we are not configured to manage...')
        return
    end

    if not ifcfg then
        print('Unable to find physical interface for TAP device ' .. ifname)
        return
    end

    print('New interface ' .. ifname .. ' index mapping is ' .. phy_idx .. ':' .. tap_idx .. ' (Snabb:Linux)')

    self.linux_map[tonumber(tap_idx)] = tonumber(phy_idx)

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
