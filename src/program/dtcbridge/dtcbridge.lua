-- Dataplane To Controlplane Bridge (DTCB)
module(..., package.seeall)

local S     = require("syscall")

local nl    = S.nl
local engine     = require("core.app")
local numa   = require("lib.numa")

local yang       = require('lib.yang.yang')

local table      = require('table')
local table_concat = table.concat
local bit_lshift = require('bit').lshift

local intel      = require('apps.intel_mp.intel_mp')
local arpsnoop   = require('apps.ipv4.arp_snoop')
local basic      = require('apps.basic.basic_apps')
local nlsock     = require('apps.socket.netlink')
local usock      = require('apps.socket.unix')
local pcap       = require('apps.pcap.pcap')
local dtcb       = require('apps.router.dtcb')
local route      = require('apps.router.route')

local lib   = require("core.lib")
local virtio = require('apps.virtio_net.virtio_net')
local tap   = require("apps.tap.tap")
local raw   = require("apps.socket.raw")
local ipv4     = require("lib.protocol.ipv4")

local ipv4_ntop  = require("lib.yang.util").ipv4_ntop

local htons, ntohs = lib.htons, lib.ntohs

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug

local function convert_ipv4(addr)
   if addr ~= nil then return ipv4:pton(ipv4_ntop(addr)) end
end

local int_idx = 1

function run(args)
    local c = config.new()

    local conf = yang.load_configuration('router.conf', { schema_name = 'snabb-router-v1'})

    local addresses      = {}
    local interfaces     = {}
    local tap_map        = {}

    for phy_if, params in pairs(conf.router_config.interface) do
        local ip       = params.address.ip
        local prefix   = params.address.prefix
        local mac      = params.mac or nil
        local tap_if   = params.tap
        local phy_name = 'phy_' .. int_idx
        local tap_name = 'tap_' .. int_idx
        local arp_name = 'arp_' .. int_idx
        local mux_name = 'mux_' .. int_idx

        assert(tap, 'No tap for '..phy_if)
        assert(mac, 'No mac for '..phy_if)

        local converted_ipv4 = convert_ipv4(ip)


        local interface = { tap_name = tap_name, phy_name = phy_name, arp_name = arp_name, mux_name = mux_name, mac = mac, ip = converted_ipv4, prefix = prefix, phy_if = phy_if }

        -- Store interface details by index
        interfaces[int_idx] = interface

        -- Store map of tap names to matching interface indexes
        tap_map[tap_if] = int_idx

        -- Configure each routable port
        log_info('Configuring ' .. params.type .. ' interface ' .. phy_if)

        config.app(c, phy_name, intel.Intel, { pciaddr = phy_if, txq = 0, rxq = 0 })

        log_info('Configuring tap interface for ' .. phy_name .. ' named ' .. tap_name)

        -- Connect to TAP interface for each routable port
        config.app(c, tap_name, tap.Tap, { name = tap_if, mtu_set=true })

        config.app(c, mux_name, basic.Join, {})

        config.app(c, arp_name, arpsnoop.ARPSnoop, { self_mac = mac, self_ip = converted_ipv4 })

        -- Link mux (Join) to dataplane int
        config.link(c, mux_name .. '.output -> ' .. phy_name .. '.input')

        -- Link dataplane interface to router
        config.link(c, phy_name .. '.output -> router.' .. phy_name)

        -- Link router output ctrl plane ifs to arp snoop south
        config.link(c, 'router.' .. tap_name .. ' -> ' .. arp_name .. '.south')

        -- Link arp north to tap input
        config.link(c, arp_name .. '.north -> ' .. tap_name .. '.input')
        config.link(c, arp_name .. '.south -> ' .. mux_name .. '.arp_in')

        -- Link routed traffic back to data plane
        config.link(c, 'router.' .. phy_name .. ' -> ' .. mux_name .. '.router_in')

        -- Link tap output back to dataplane interface
        config.link(c, tap_name .. '.output -> ' .. mux_name .. '.tap_in')

        int_idx = int_idx + 1
    end

    -- Create loopback interface
    -- config.app(c, 'loopback', tap.Tap, { name = 'loop0', mtu_set=true })

  --  config.app(c, "tee", basic.Tee, {})

    -- Configure
    config.app(c, 'router', route.Route, { fib_app = 'fib', interfaces = interfaces, tap_map = tap_map })
   -- config.app(c,  'router', zapi.zAPIRouterCtrl, { addresses = addresses, interfaces = interfaces } )
   -- config.app(c,  'ctrlsock',  usock.UnixSocket, { filename = conf.router_config.socket, listen = true, mode = 'stream'})
   --  config.link(c, 'ctrlsock.tx -> router.ctrl')
   --  config.link(c, 'router.ctrl -> ctrlsock.rx')

    config.app(c,  'fib',  nlsock.Netlink, { interfaces = interfaces, tap_map = tap_map })

    numa.unbind_numa_node()
    numa.bind_to_cpu(2)
    numa.prevent_preemption(1)


    engine.busywait = true
    engine.configure(c)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
