module(..., package.seeall)

local S     = require("syscall")

local engine     = require("core.app")

local yang = require('lib.yang.yang')

local config     = require("core.config")
local worker     = require("core.worker")
local leader     = require("apps.config.leader")
local follower   = require("apps.config.follower")
local router     = require("apps.router.router")


local pci   = require("lib.hardware.pci")
local lib   = require("core.lib")
local json  = require("lib.json")
local tap   = require("apps.tap.tap")
local raw   = require("apps.socket.raw")
local vlan  = require("apps.vlan.vlan")

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug

local int_ctr = 1

function gen_ports(incoming, outgoing)
    return { incoming = incoming, outgoing = outgoing }
end

-- Select the correct driver for the interface.
-- Return the ifname, and the correct name for the incoming and outgoing ports.
function config_interface(c, interface)
    local ifname = "int_" .. interface

    -- Handle tap/tun interfaces
    if string.find(interface, "tap") == 1 or string.find(interface, "tun") == 1 then
        log_debug('Interface %s is tun/tap', interface)
        config.app(c, ifname, tap.Tap, interface)
        return ifname, gen_ports('output', 'input')
    end

    -- Handle hardware interfaces
    if pci.qualified(interface) then
        local dev = pci.device_info(interface)
        if not dev.driver then
            log_error("No driver available for PCI device %s, vendor %s", interface, dev.vendor or 'Unknown')
            return nil
        end
        local device = dev.device
        local driver_module = require(dev.driver)

        if device == '0x1521' or device == '0x1533' or device == '0x157b' then
            log_debug("Interface %s is Intel1g...", interface)
            config.app(c, ifname, driver_module.Intel1g, {
                pciaddr = interface,
                rxq = int_ctr,
            })
        else
            log_debug("Interface %s is Intel82599...", interface)
            config.app(c, ifname, driver_module.Intel82599, {
                pciaddr = interface,
                rxq = int_ctr,
            })
        end

        int_ctr = int_ctr + 1
        return ifname, gen_ports('tx', 'rx')
    end

    -- Assume anything still here is a RawSocket device
    log_debug("Interface %s is RawSocket...", interface)
    config.app(c, ifname, raw.RawSocket, interface)
    return ifname, gen_ports('output', 'input')
end

function run (args)
    local c = config.new()

    local conf = yang.load_configuration('router.conf', { schema_name = 'snabb-router-v1'})

    -- Create L3 router App
    config.app(c, "router", router.zAPIRouter, conf)

    for int_name, params in pairs(conf.router_config.interface) do
        log_info('Configuring ' .. params.type .. ' interface ' .. int_name)
        local interface, ports = config_interface(c, int_name)

        if not interface then
            log_critical("Unable to configure interface %s!", int_name)
            main.exit(1)
        end

        -- Link all apps to router
        config.link(c, interface .. '.' .. ports.incoming ..' -> router.' .. params.type)
    end

    engine.busywait = false
    engine.configure(c)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
