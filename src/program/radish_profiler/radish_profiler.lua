module(..., package.seeall)

local S     = require("syscall")

local pci   = require("lib.hardware.pci")
local lib   = require("core.lib")
local json  = require("lib.json")
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

local usage = require("program.radish_profiler.README_inc")

local long_opts = {
    help     = "h",
    config   = "c",
    input    = "i",
    output   = "o",
    group    = "g",
    core     = "n",
    busywait = "b",
    invlan   = 1,
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
        config_file_path = "/etc/radish/profiler.json",
        int_in  = {},
        int_out = {},
    }

    local handlers = {}
    function handlers.h (arg) print(usage) main.exit(1) end
    function handlers.c (arg) opt.config_file_path = arg end
    function handlers.i (arg)
        table.insert(opt.int_in, arg)
    end
    function handlers.o (arg)
        table.insert(opt.int_out, arg)
    end
    function handlers.g (arg) opt.group            = arg end
    function handlers.n (arg) opt.core             = arg end
    function handlers.b (arg) opt.busywait         = true end
    function handlers.invlan (arg)
        local vlans = {}
        for vlan in string.gmatch(arg, '([^,]+)') do
            vlans[#vlans+1] = tonumber(vlan)
        end
        opt.in_vlan = vlans
    end

    args = lib.dogetopt(args, handlers, "hc:i:o:g:c:n:b", long_opts)

    if #opt.int_in < 1 then
        log_critical("Missing argument -i")
        main.exit(1)
    end

    if #opt.int_out < 1 then
        log_warn("Not forwarding captured traffic...")
    end

    if not file_exists(opt.config_file_path) then
        log_critical("Config file '%s' does not exist!", opt.config_file_path)
        main.exit(1)
    end

    if opt.in_vlan then
        log_info("Accepting VLAN tags %s from input interfaces %s", table.concat(opt.in_vlan,", "), table.concat(opt.int_in, ", "))
    end


    return opt
end

function config_interface(c, interface)
    local ifname = "int_"..interface

    -- Handle tap/tun interfaces
    if string.find("tap", interface) == 0 or string.find("tun", interface) == 0 then
        log_info("Interface %s is tap/tun...", interface)
        config.app(c, ifname, tap.Tap, interface)
        return ifname
    end

    -- Handle hardware interfaces
    if pci.qualified(interface) then
        local dev = pci.device_info(interface)
        if not dev.driver then
            log_info("No driver available for PCI device %s, vendor %s", interface, dev.vendor or 'Unknown')
            return nil
        end
        local device = dev.device
        local driver_module = require(dev.driver)

        log_info("Interface driver is %s", model)

        if device == '0x1521' or device == '0x1533' or device == '0x157b' then
            log_info("Interface %s is Intel1g...", interface)
            config.app(c, ifname, driver_module.Intel1g, {
                pciaddr = interface,
                rxq = 0,
            })
        else
            log_info("Interface %s is Intel82599...", interface)
            config.app(c, ifname, driver_module.Intel82599, {
                pciaddr = interface,
                rxq = 0,
            })
        end

        return ifname
    end

    -- Assume anything still here is a RawSocket device
    log_info("Interface %s is RawSocket...", interface)
    return raw.RawSocket
end

function run (args)
    local opt = parse_args(args)

    -- Bind to a core
    if opt.core then
        log_info("Binding to core %d", opt.core)
    end

    S.sched_setaffinity(nil, {opt.core or 0})

    local c = config.new()

    config.app(c, "ddos", ddos.Detector, {config_file_path = opt.config_file_path})

    config.app(c, "vlanmux", vlan.VlanMux)

    -- Configure input interfaces, redirecting packets to vlanmux.trunk
    -- if in_vlan is set or passing directly to ddos.input if not.
    for _, interface in ipairs(opt.int_in) do
        local int_name = config_interface(c, interface)
        if not int_name then
            log_critical("Unable to configure app for interface %s!", interface)
            main.exit(1)
        end

        if opt.in_vlan then
            config.link(c, int_name .. ".output -> vlanmux.trunk")
        else
            config.link(c, int_name .. ".output -> ddos.input")
        end
    end

    -- Configure output interfaces, sourced from ddos.output
    for _, interface in ipairs(opt.int_out) do
        local int_name = config_interface(c, interface)
        if not int_name then
            log_critical("Unable to configure app for interface %s!", interface)
            main.exit(1)
        end

        config.link(c, "ddos.output -> " .. int_name .. ".input")
    end

    if opt.in_vlan then
        for _, vlan in ipairs(opt.in_vlan) do
            -- Deal with native vlan (i.e. untagged)
            if vlan == 0 then
                vlan = "native"
            else
                vlan = "vlan" .. vlan
            end

            config.link(c, "vlanmux." .. vlan ..  " -> ddos.input")
        end
    end

    engine.busywait = opt.busywait and true or false
    engine.configure(c)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
