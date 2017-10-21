-- Multi-process Snabb Router
module(..., package.seeall)

local app        = require("core.app")
local config     = require("core.config")
local worker     = require("core.worker")

local engine     = require("core.app")
local numa       = require("lib.numa")
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

function run_worker(worker_id, cfg_file)
    print('Running worker as follower ' .. tostring(worker_id))
    print('Using config file ' .. cfg_file)

    local conf = yang.load_configuration(cfg_file, { schema_name = 'snabb-router-v1' })

    local graph = config.new()

    local int_idx = 1

    local addresses      = {}
    local interfaces     = {}
    local tap_map        = {}

    for phy_if, params in pairs(conf.router_config.interface) do
	local ip       = params.address.ip
	local prefix   = params.address.prefix
	local mac      = params.mac or nil
	local mtu      = params.mtu or 1500
	local tap_if   = params.tap
	local phy_name = 'phy_' .. int_idx
	local tap_name = 'tap_' .. int_idx
	local arp_name = 'arp_' .. int_idx
	local mux_name = 'mux_' .. int_idx

	assert(tap_if, 'No tap for '..phy_if)
	assert(mac, 'No mac for '..phy_if)

	local converted_ipv4 = convert_ipv4(ip)


	local interface = { tap_name = tap_name, phy_name = phy_name, mux_name = mux_name, mac = mac, ip = converted_ipv4, prefix = prefix, phy_if = phy_if, tap_if = tap_if, mtu = mtu }

	-- Store interface details by index
	interfaces[int_idx] = interface

	-- Store map of tap names to matching interface indexes
	tap_map[tap_if] = int_idx

	-- Configure each routable port
	log_info('Configuring ' .. params.type .. ' interface ' .. phy_if .. ' with {r,t}xq = ' .. tostring(worker_id))

	config.app(graph, phy_name, intel.Intel, { pciaddr = phy_if, txq = worker_id, rxq = worker_id, fdir = true, fdir_filters = {{ src_addr = nil, dst_addr = ip, queue = 0 }}, run_stats=true })

	-- Link dataplane interface to router
	config.link(graph, phy_name .. '.output -> router.' .. phy_name)

        -- If worker ID is 0 then we are master of all interfaces
        -- Take control of the linked TAP interface
        if worker_id == 0 then
	    log_info('Configuring tap interface for ' .. phy_name .. ' named ' .. tap_name)

	    -- Create tap interface
	    config.app(graph, tap_name, tap.Tap, { name = tap_if, mtu_set=true })

            -- Create mux, as we have multiple output ports (tap + router) back to one physical if
	    config.app(graph, mux_name, basic.Join, {})

	    -- Link router output ctrl plane ifs to tap device
	    config.link(graph, 'router.' .. tap_name .. ' -> ' .. tap_name .. '.input')

	    -- Link tap output back to dataplane interface
	    config.link(graph, tap_name .. '.output -> ' .. mux_name .. '.tap_in')

	    -- Link mux (Join) to dataplane int
	    config.link(graph, mux_name .. '.output -> ' .. phy_name .. '.input')

	    -- Link routed traffic back to data plane
	    config.link(graph, 'router.' .. phy_name .. ' -> ' .. mux_name .. '.router_in')


        -- If we're not interface master, we have no tap, which means we need no mux.
        else
	    -- Link routed traffic back to data plane
	    config.link(graph, 'router.' .. phy_name .. ' -> ' .. phy_name .. '.input')
        end

	int_idx = int_idx + 1
    end

    -- Create loopback interface
    -- config.app(graph, 'loopback', tap.Tap, { name = 'loop0', mtu_set=true })

    -- Configure
    config.app(graph, 'router', route.Route, { fib_app = 'fib', interfaces = interfaces, tap_map = tap_map })
    config.app(graph,  'fib',  nlsock.Netlink, { interfaces = interfaces, tap_map = tap_map })

    app.configure(graph)
    app.busywait = false
    app.main({})
end

function run(args)
    local graph = config.new()

    local function setup_fn(cfg_file)
    end


    local cfg_file = args[1] or 'router.conf'

    local processes = 4


    local worker_code = "require('program.snabbrouter.snabbrouter').run_worker(%d, '%s')"

    local follower_pids = {}

    for i = 1, processes+1 do
        print('Spawning process ' .. tostring(i))
        follower_pids[#follower_pids+1] = worker.start("router_" .. tostring(i), worker_code:format(i, cfg_file))
    end


    run_worker(0, cfg_file)
end

function selftest()
    run({})
end
