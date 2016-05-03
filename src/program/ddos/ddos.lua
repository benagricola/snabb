module(..., package.seeall)

local S     = require("syscall")

local lib   = require("core.lib")
local json  = require("lib.json")
local intel = require("apps.intel.intel_app")
local tap   = require("apps.tap.tap")
local raw   = require("apps.socket.raw")
local vlan  = require("apps.vlan.vlan")
local ddos  = require("apps.ddos.ddos")

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug

local usage = require("program.ddos.README_inc")

local long_opts = {
    help     = "h",
    config   = "c",
    input    = "i",
    output   = "o",
    group    = "g",
    core     = "n",
    busywait = "b",
    invlan   = 1,
    outvlan  = 2,
}

local function fatal(msg,...)
   print('ERROR: ' .. msg:format(...))
   main.exit(1)
end

local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end

local function dir_exists(path)
   local stat = S.stat(path)
   return stat and stat.isdir
end

local function nic_exists(pci_addr)
   local devices="/sys/bus/pci/devices"
   return dir_exists(("%s/%s"):format(devices, pci_addr)) or
      dir_exists(("%s/0000:%s"):format(devices, pci_addr))
end

local function tuntap_exists(device)
    -- Check for tun_flags, this exists if the device is tun/tap
    local devices="/sys/devices/virtual/net/%s/tun_flags"
    return file_exists(devices:format(device))
end

function parse_args(args)
    local opt = {
        report = false,
        config_file_path = "/etc/ddos/ddos.json",
    }

    local handlers = {}
    function handlers.h (arg) print(usage) main.exit(1) end
    function handlers.c (arg) opt.config_file_path = arg end
    function handlers.i (arg) opt.int_in           = arg end
    function handlers.o (arg) opt.int_out          = arg end
    function handlers.g (arg) opt.group            = arg end
    function handlers.n (arg) opt.core             = arg end
    function handlers.b (arg) opt.busywait         = true end
    function handlers.invlan (arg) opt.in_vlan     = tonumber(arg) end
    function handlers.outvlan (arg) opt.out_vlan   = tonumber(arg) end


    args = lib.dogetopt(args, handlers, "hc:i:o:g:c:n:b", long_opts)

    if not opt.int_in then
        log_critical("Missing argument -i")
        main.exit(1)
    end

    if not file_exists(opt.config_file_path) then
        log_critical("Config file '%s' does not exist!", opt.config_file_path)
        main.exit(1)
    end

    if opt.in_vlan then
        log_info("Stripping VLAN %d from input interface %s", opt.in_vlan, opt.int_in)
    end

    if not opt.int_out then
        log_info("Not forwarding captured traffic...")
    else
        if opt.out_vlan then
            log_info("Stripping VLAN %d from output interface %s", opt.out_vlan, opt.int_out)
        end

    end

    return opt
end

function run (args)
    local opt = parse_args(args)

    -- Bind to a core
    S.sched_setaffinity(nil, {opt.core or 0})

    local c = config.new()

    config.app(c, "ddos", ddos.Detector, {config_file_path = opt.config_file_path})

    config.app(c, "vlanmux", vlan.VlanMux)

    -- If input VLAN is specified, place untagger between input interface and DDoS detector
    local demux_link
    if opt.in_vlan then
        demux_link = "vlan" .. opt.in_vlan
    else
        demux_link = "native"
    end

    -- If this is a physical NIC then initialise 82599 driver
    if nic_exists(opt.int_in) then
        log_info("Input interface %s is physical device, initialising...", opt.int_in)
        config.app(c, "int_in", intel.Intel82599, {
            pciaddr = opt.int_in,
        })
        config.link(c, "int_in.tx -> vlanmux.trunk")

    -- Otherwise check for a tun/tap device
    elseif tuntap_exists(opt.int_in) then
        log_info("Input interface %s is tun/tap device, initialising...", opt.int_in)
        config.app(c, "int_in", tap.Tap, opt.int_in)
        config.link(c, "int_in.output -> vlanmux.trunk")

    -- Otherwise assume rawsocket
    else
        log_info("Input interface %s is unknown device, initialising as RawSocket...", opt.int_in)
        config.app(c, "int_in", raw.RawSocket, opt.int_in)
        config.link(c, "int_in.tx -> vlanmux.trunk")
    end

    config.link(c, "vlanmux." .. demux_link .. " -> ddos.input")

    if opt.int_out then
        -- If this is a physical NIC then initialise 82599 driver
        if nic_exists(opt.int_out) then
            log_info("Output interface %s is physical device, initialising...", opt.int_out)
            config.app(c, "int_out", intel.Intel82599, {
                pciaddr = opt.int_out,
            })
            config.link(c, output_link .. " -> int_out.rx")
        -- Otherwise check for a tun/tap device
        elseif tuntap_exists(opt.int_out) then
            log_info("Output interface %s is tun/tap device, initialising...", opt.int_out)
            config.app(c, "int_out", raw.RawSocket, opt.int_out)
            config.link(c, output_link .. " -> int_out.rx")
        -- Otherwise assume rawsocket
        else
            log_info("Output interface %s is unknown device, initialising as RawSocket...", opt.int_out)
            config.app(c, "int_out", tap.Tap, opt.int_out)
            config.link(c, output_link .. " -> int_out.input")

        end

    end

    engine.busywait = opt.busywait and true or false
    engine.configure(c)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
