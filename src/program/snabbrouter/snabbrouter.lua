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
local interlink   = require('apps.interlink.mapper')

local nlf_parent = require('apps.router.nlforwarder')
local nlf_child  = require('apps.router.forwarder_child')

local lib         = require("core.lib")
local tap         = require("apps.tap.tap")
local ipv4        = require("lib.protocol.ipv4")
local ipv4_ntop   = require("lib.yang.util").ipv4_ntop

local function convert_ipv4(addr)
   if addr ~= nil then return ipv4:pton(ipv4_ntop(addr)) end
end

function run_fib(worker_id, processes, interfaces)
    local graph = config.new()

    print('Configuring FIB on process ' .. tostring(worker_id))

    config.app(graph, 'interlink', interlink, {})

    -- Create master forwarder copy
    config.app(graph, 'fib',  nlf_parent.NLForwarder, {
        fib_mode='248',
        interfaces=interfaces,
    })

    config.app(graph, 'flood', basic.Tee, {})

    -- Allow child fib to send traffic to master fib
    config.link(graph, 'interlink.to_master -> fib.from_children')

    -- Allow master fib to floow back to child fib
    config.link(graph, 'fib.to_children -> flood.input')


    for _, interface in ipairs(interfaces) do
	-- Allow master fib to send traffic directly to taps
	config.link(graph, 'fib.' .. interface.tap_name .. ' -> interlink.' .. interface.tap_name)

	-- Allow master fib to send traffic directly back to phy
	config.link(graph, 'fib.' .. interface.phy_name .. ' -> interlink.' .. interface.phy_name)
    end

    -- Create input link for each worker process
    for i = 0, processes do
        if i ~= worker_id then
            config.link(graph, 'flood.output -> interlink.proc_' .. worker_id)
        end
    end

    app.configure(graph)
    app.busywait = false
    app.main({})

end

function run_forwarder(worker_id, processes, interfaces)
    local graph = config.new()

    config.app(graph, 'interlink', interlink, {})

    -- Create child forwarder copy
    config.app(graph, 'forwarder',  nlf_child.ForwarderChild, {
	fib_mode='248',
	interfaces=interfaces,
	id=worker_id,
    })

    -- Allow child fib to send traffic to master fib
    config.link(graph, 'forwarder.to_master -> interlink.to_master')

    -- Allow master fib to flood back to child fib
    config.link(graph, 'interlink.proc_' .. worker_id .. ' -> forwarder.from_master')

    for _, interface in ipairs(interfaces) do

        local is_master_proc = (interface.master_proc == worker_id)

	-- Allow master fib to send traffic directly to taps
	config.link(graph, 'forwarder.' .. interface.tap_name .. ' -> interlink.' .. interface.tap_name)

	-- Allow master fib to send traffic directly back to phy
	config.link(graph, 'forwarder.' .. interface.phy_name .. ' -> interlink.' .. interface.phy_name)


	-- We want to assign rxq0 to the master process for this interface
	local queue
	if worker_id < interface.master_proc then
	    queue = (processes - interface.master_proc) + worker_id
	else
	    queue = (processes - interface.master_proc) - (processes - worker_id)
	end

	-- Configure physical nic access for non-fib processes
        if is_master_proc then
            print('Configuring interface ' .. tostring(interface.phy_if) .. '/q' .. queue .. ' master on process ' .. tostring(worker_id))
            config.app(graph, interface.phy_name, intel.Intel, { pciaddr = interface.phy_if, txq = queue, rxq = queue, master_stats = true })

	    print('Creating tap ' .. interface.tap_if .. ' on process ' .. tostring(worker_id))
	    config.app(graph, interface.tap_name, tap.Tap, { name = interface.tap_if, mtu_set=true })

            -- Create input and output mux on master
	    config.app(graph, interface.out_mux_name, basic.Join, {})
	    config.app(graph, interface.in_mux_name, basic.Join, {})

	    -- Receive interlink tap traffic onto mux
	    config.link(graph, 'interlink.' .. interface.tap_name .. ' -> ' .. interface.in_mux_name .. '.ipc_in')

	    -- Link router output ctrl plane to input mux input
	    config.link(graph, 'forwarder.' .. interface.tap_name .. ' -> ' .. interface.in_mux_name .. '.router_in')

	    -- Link input mux output to tap input
	    config.link(graph, interface.in_mux_name .. '.output -> ' .. interface.tap_name .. '.input')

	    -- Link tap output back to output mux input
	    config.link(graph, interface.tap_name .. '.output -> ' .. interface.out_mux_name .. '.tap_in')

	    -- Link locally routed traffic back to output mux input
	    config.link(graph, 'forwarder.' .. interface.phy_name .. ' -> ' .. interface.out_mux_name .. '.router_in')

	    -- Link output interlink back to output mux input
	    config.link(graph, 'interlink.' .. interface.phy_name .. ' -> ' .. interface.out_mux_name .. '.ipc_in')

	    -- Link output mux back to phy input
	    config.link(graph, interface.out_mux_name .. '.output -> ' .. interface.phy_name .. '.input')

	    -- Link phy input to router
	    config.link(graph, interface.phy_name .. '.output -> forwarder.' .. interface.phy_name)
	else
	    print('Configuring interface ' .. tostring(interface.phy_if) .. '/q' .. queue .. ' child on process ' .. tostring(worker_id))
	    config.app(graph, interface.phy_name, intel.Intel, { pciaddr = interface.phy_if, txq = queue, rxq = queue, run_stats = true })

	    -- Link routed traffic back to phy input
	    config.link(graph, 'forwarder.' .. interface.phy_name .. ' -> ' .. interface.phy_name .. '.input')

	    -- When not master, we need to send tap traffic cross-process.
	    -- Use the named interlink to forward the traffic.
	    config.link(graph, 'forwarder.' .. interface.tap_name .. ' -> interlink.' .. interface.tap_name)

	    -- Link phy input to router
	    config.link(graph, interface.phy_name .. '.output -> forwarder.' .. interface.phy_name)
	end
    end

    app.configure(graph)
    app.busywait = false
    app.main({})
end

function run_worker(worker_id, processes, cfg_file, fib_only)
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
	local phy_name     = 'phy_' .. int_idx
        local fib_name_in  = 'fibin_' .. phy_name
        local fib_name_out = 'fibout_' .. phy_name
	local tap_name     = 'tap_' .. int_idx
        local out_mux_name = 'outmux_' .. int_idx
	local in_mux_name  = 'inmux_' .. int_idx

	assert(tap_if, 'No tap for '..phy_if)
	assert(mac, 'No mac for '..phy_if)

        local master_proc = (int_idx % processes)

        local converted_ipv4 = convert_ipv4(ip)

        local interface = {
            tap_name     = tap_name,
            phy_name     = phy_name,
            fib_name_in  = fib_name_in,
            fib_name_out = fib_name_out,
            out_mux_name = out_mux_name,
            in_mux_name  = in_mux_name,
            mac          = mac,
            ip           = converted_ipv4,
            master_proc  = master_proc,
            prefix       = prefix,
            phy_if       = phy_if,
            tap_if       = tap_if,
            mtu          = mtu,
        }

        -- Insert interface by index
        interfaces[int_idx] = interface

        -- Increment interface index
        int_idx = int_idx + 1
    end

    if fib_only then
        run_fib(worker_id, processes, interfaces)
    else
        run_forwarder(worker_id, processes, interfaces)
    end
end

function run(args)
    local graph = config.new()

    local function setup_fn(cfg_file)
    end


    local cfg_file = args[1] or 'router.conf'

    local processes = 1

    local worker_code = "require('program.snabbrouter.snabbrouter').run_worker(%d, %d, '%s', %s)"

    local follower_pids = {}

    -- Start FIB process
    worker.start("fib", worker_code:format(999, processes, cfg_file, tostring(true)))

    for i = 1, processes do
        print('Spawning process ' .. tostring(i))
        follower_pids[#follower_pids+1] = worker.start("router_" .. tostring(i), worker_code:format(i-1, processes, cfg_file, tostring(false)))
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
