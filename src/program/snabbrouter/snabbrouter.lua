-- Multi-process Snabb Router
module(..., package.seeall)

local app         = require("core.app")
local config      = require("core.config")
local worker      = require("core.worker")

local engine      = require("core.app")
local numa        = require("lib.numa")
local yang        = require('lib.yang.yang')

local shm         = require("core.shm")
local table       = require('table')
local bit_lshift  = require('bit').lshift

local ffi         = require("ffi")
local C           = ffi.C

local basic       = require('apps.basic.basic_apps')
local intel       = require('apps.intel_mp.intel_mp')
local nlforwarder = require('apps.router.nlforwarder')

local lib         = require("core.lib")
local tap         = require("apps.tap.tap")
local ipv4        = require("lib.protocol.ipv4")
local ipv4_ntop   = require("lib.yang.util").ipv4_ntop

local function convert_ipv4(addr)
   if addr ~= nil then return ipv4:pton(ipv4_ntop(addr)) end
end

function run_worker(worker_id, processes, cfg_file)
    local conf = yang.load_configuration(cfg_file, { schema_name = 'snabb-router-v1' })

    local graph = config.new()

    local interfaces = {}
    local tap_map    = {}
    local int_idx    = 1

    for phy_if, params in pairs(conf.router_config.interface) do
      	local ip           = params.address.ip
	local prefix       = params.address.prefix
	local mac          = params.mac or nil
	local mtu          = params.mtu or 1500
	local tap_if       = params.tap
        local ipl_name     = 'ipl_' .. tap_name
        local group_name   = 'group/' .. ipl_name
	local phy_name     = 'phy_' .. int_idx
	local tap_name     = 'tap_' .. int_idx
        local out_mux_name = 'outmux_' .. int_idx
	local in_mux_name  = 'inmux_' .. int_idx


	assert(tap_if, 'No tap for '..phy_if)
	assert(mac, 'No mac for '..phy_if)

        local master_proc = (int_idx % processes)

        local is_master_proc = (master_proc == worker_id)

        local converted_ipv4 = convert_ipv4(ip)

        -- Each process gets an inter-process link for each if
	local p_link = link.new(ipl_name)
	shm.alias(group_name, "links/" .. ipl_name)

        local interface = {
            tap_name    = tap_name,
            phy_name    = phy_name,
            mux_name    = out_mux_name,
            mac         = mac,
            ip          = converted_ipv4,
            master_proc = master_proc,
            prefix      = prefix,
            phy_if      = phy_if,
            tap_if      = tap_if,
            mtu         = mtu,
        }

        local phy_cfg = { pciaddr = phy_if, txq = worker_id, rxq = worker_id }

        if is_master_proc then
            print('Configuring interface ' .. tostring(phy_if) .. ' master on process ' .. tostring(worker_id))

            -- Collect master stats
            phy_cfg.master_stats = true

            config.app(graph, tap_name, tap.Tap, { name = tap_if, mtu_set=true })

            config.app(graph, out_mux_name, basic.Join, {})

            -- No input mux required as yet since forwarder will handle IPC
            -- config.app(graph, in_mux_name,  basic.Join, {})

            -- Link router output ctrl plane to tap input
            config.link(graph, 'forwarder.' .. tap_name .. ' -> ' .. tap_name .. '.input')

            -- Link tap output back to output mux input
            config.link(graph, tap_name .. '.output -> ' .. out_mux_name .. '.tap_in')

            -- Link routed traffic back to output mux input
	    config.link(graph, 'forwarder.' .. phy_name .. ' -> ' .. out_mux_name .. '.router_in')

            -- Link output mux back to phy input
            config.link(graph, out_mux_name .. '.output -> ' .. phy_name .. '.input')

            -- Attach input ipc link to input mux name
            config.attach(graph, 'in_mux_name', ipl_name, group_name, 'input')


        else
            print('Configuring interface ' .. tostring(phy_if) .. ' slave on process ' .. tostring(worker_id))
            phy_cfg.run_stats = true

            -- Link routed traffic back to phy input
            config.link(graph, 'forwarder.' .. phy_name .. ' -> ' .. phy_name .. '.input')

        end

        config.app(graph, phy_name, intel.Intel, phy_cfg)

        -- Link phy input to router
	config.link(graph, phy_name .. '.output -> forwarder.' .. phy_name)


        -- Insert interface by index
        interfaces[int_idx] = interface

        -- Increment interface index
        int_idx = int_idx + 1
    end

    -- Forwarder handles all inter-process communications.
    config.app(graph,  'forwarder',  nlforwarder.NLForwarder, {
        master=true,
        fib_mode='dxr',
        netlink_type='route',
        interfaces=interfaces,
    })

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


    local worker_code = "require('program.snabbrouter.snabbrouter').run_worker(%d, %d, '%s')"

    local follower_pids = {}

    for i = 1, processes do
        print('Spawning process ' .. tostring(i))
        follower_pids[#follower_pids+1] = worker.start("router_" .. tostring(i), worker_code:format(i, processes, cfg_file))
    end

    while true do
	for w, s in pairs(worker.status()) do
	   print(("  worker %s: pid=%s alive=%s"):format(
		 w, s.pid, s.alive))
	end
        C.sleep(1)
    end
end

function selftest()
    run({})
end
