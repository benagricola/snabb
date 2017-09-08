module(..., package.seeall)

local S     = require("syscall")

local engine     = require("core.app")

local yang       = require('lib.yang.yang')

local bit_lshift = require('bit').lshift

local basic      = require('apps.basic.basic_apps')
local usock      = require('apps.socket.unix')
local pcap       = require('apps.pcap.pcap')
local config     = require("core.config")
local worker     = require("core.worker")
local leader     = require("apps.config.leader")
local follower   = require("apps.config.follower")
local router     = require("apps.router.router")

local lwipv4 = require("apps.lwaftr.ipv4_apps")
local lwutil = require("apps.lwaftr.lwutil")

local wr16, rd32, wr32 = lwutil.wr16, lwutil.rd32, lwutil.wr32


local pci   = require("lib.hardware.pci")
local lib   = require("core.lib")
local json  = require("lib.json")
local tap   = require("apps.tap.tap")
local raw   = require("apps.socket.raw")
local arp   = require("apps.ipv4.arp")
local vlan  = require("apps.vlan.vlan")
local ipv4     = require("lib.protocol.ipv4")

local ipv4_ntop  = require("lib.yang.util").ipv4_ntop

local htons, ntohs = lib.htons, lib.ntohs

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug

local ffi = require('ffi')
local ffi_string = ffi.string
local packet = require('core.packet')

local int_ctr = 1

local function convert_ipv4(addr)
   if addr ~= nil then return ipv4:pton(ipv4_ntop(addr)) end
end


-- Stolen from apps/ipv4/arp.lua as it's localled
local function random_mac()
   local mac = lib.random_bytes(6)
   -- Bit 0 is 0, indicating unicast.  Bit 1 is 1, indicating locally
   -- administered.
   mac[0] = bit_lshift(mac[0], 2) + 2
   return mac
end

local function gen_ports(incoming, outgoing)
    return { incoming = incoming, outgoing = outgoing }
end

local printapp = {}
function printapp:new (name)
  return {
     push = function(self)
	local l = self.input.rx
	if l == nil then return end
	while not link.empty(l) do
	   local p = link.receive(l)
	   print(name..': ', p.length, ffi_string(p.data, p.length))
	   packet.free(p)
	end
     end
  }
end

-- Select the correct driver for the interface.
-- Return the ifname, and the correct name for the incoming and outgoing ports.
local function config_interface(c, interface)
    local ifname = "int_" .. interface

    -- Handle tap/tun interfaces
    if string.find(interface, "tap") == 1 or string.find(interface, "tun") == 1 then
        log_debug('Interface %s is tun/tap', interface)
	config.app(c, ifname, raw.RawSocket, interface)
	return ifname, gen_ports('output', 'input')
        --config.app(c, ifname, tap.Tap, { name = interface, mtu = 1500, mtu_fixup = false, mtu_offset = 0 })
        --return ifname, gen_ports('output', 'input')
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

function run(args)
    local c = config.new()

    local conf = yang.load_configuration('router.conf', { schema_name = 'snabb-router-v1'})

    local addresses = {}

    local interfaces = {}

    for int_name, params in pairs(conf.router_config.interface) do
        local ip     = params.address.ip
        local prefix = params.address.prefix
        local mac    = params.mac or nil

        -- TODO: Hand off Multiple IPs to ARP / Router
        log_info('Configuring ' .. params.type .. ' interface ' .. int_name .. ' with address ' .. ipv4_ntop(ip) .. '/' .. prefix)
        local interface, ports = config_interface(c, int_name)

        if not interface then
            log_critical("Unable to configure interface %s!", int_name)
            main.exit(1)
        end

        local converted_ipv4 = convert_ipv4(ip)

        addresses[#addresses+1] = { ip = converted_ipv4, prefix = prefix }

        -- Allocate random mac addr for this interface
        if not mac then
            mac = random_mac()
        end

        config.app(c, "arp_" .. int_name, arp.ARP, { self_ip = converted_ipv4, self_mac = mac, next_ip = ipv4:pton('10.231.14.2') })


        interfaces[#interfaces+1] = { name = int_name, mac = mac, ip = converted_ipv4, prefix = prefix }

        config.app(c, "icmp_" .. int_name, lwipv4.ICMPEcho, { address = converted_ipv4 })

        -- Link interface to ARP handler
        config.link(c, interface .. '.' .. ports.incoming .. ' -> arp_' .. int_name .. '.south')
        config.link(c, 'arp_' .. int_name .. '.south -> ' .. interface .. '.' .. ports.outgoing)

        -- Link ARP handler to ICMP Handler
        config.link(c, 'arp_' .. int_name .. '.north -> icmp_' .. int_name .. '.south')
        config.link(c, 'icmp_' .. int_name .. '.south -> arp_' .. int_name .. '.north')
        --
        -- Link all apps to router
--        config.link(c, 'icmp_' .. int_name .. '.north -> router.' .. params.type)
--        config.link(c, 'router.' .. params.type .. ' -> icmp_' .. int_name .. '.north')
        config.link(c, 'icmp_' .. int_name .. '.north -> teein.input')
        config.link(c, 'teein.output -> router.' .. params.type)
        config.link(c, 'teein.output -> pcapwin.input')
        config.link(c, 'teeout.output -> icmp_' .. int_name .. '.north')
        config.link(c, 'teeout.output -> pcapwout.input')
        config.link(c, 'router.' .. params.type .. ' -> teeout.input')
    end

    -- Create zAPIRouterControl App. This can be configured to load routes into other apps
    config.app(c, "router", router.zAPIRouterCtrl, { addresses = addresses, interfaces = interfaces } )

    config.app(c, "ctrlsock",  usock.UnixSocket, { filename = conf.router_config.socket, listen = true, mode = 'stream'})
    config.link(c, 'ctrlsock.tx -> router.ctrl')
    config.link(c, 'router.print -> print.rx')
    config.link(c, 'router.ctrl -> ctrlsock.rx')

    config.app(c, "print", printapp, 'router')
    config.app(c, "teeout", basic.Tee, {})
    config.app(c, "teein", basic.Tee, {})
    config.app(c, "pcapwout",  pcap.PcapWriter, '/u/out.pcap')
    config.app(c, "pcapwin",  pcap.PcapWriter, '/u/in.pcap')

    engine.busywait = false
    engine.configure(c)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
