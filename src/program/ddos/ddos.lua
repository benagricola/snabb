module(..., package.seeall)

local S     = require("syscall")

local lib   = require("core.lib")
local json  = require("lib.json")
local intel = require("apps.intel.intel_app")
local tap   = require("apps.tap.tap")
local ddos  = require("apps.ddos.ddos")

local usage = require("program.ddos.README_inc")

local long_opts = {
    help     = "h",
    config   = "c",
    input    = "i",
    output   = "o",
    group    = "g",
    core     = "n",
    busywait = "b",
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


    args = lib.dogetopt(args, handlers, "hc", long_opts)

    if not opt.int_in then fatal("Missing argument -i") end
    if not opt.int_out then print("Not forwarding captured traffic") end

    if not file_exists(opt.config_file_path) then
        fatal("Config file '%s' does not exist!", opt.config_file_path)
    end
    return opt
end

function run (args)
    local opt = parse_args(args)

    -- Bind to a core
    S.sched_setaffinity(nil, {opt.core or 0})

    local c = config.new()

    config.app(c, "ddos", ddos.Detector, {config_file_path = opt.config_file_path})

    -- If this is a physical NIC the initialise 82599 driver
    if nic_exists(opt.int_in) then
        config.app(c, "int_in", intel.Intel82599, {
            pciaddr = opt.int_in,
        })
        config.link(c, "int_in.rx -> ddos.input")

    -- Otherwise assume TAP device
    else
        config.app(c, "int_in", tap.Tap, opt.int_in)
        config.link(c, "int_in.output -> ddos.input")
    end

    if opt.int_out then
        if nic_exists(opt.int_out) then
            config.app(c, "int_out", intel.Intel82599, {
                pciaddr = opt.int_out,
            })
            config.link(c, "ddos.output -> int_out.tx")
        else
            config.app(c, "int_out", tap.Tap, opt.int_out)
            config.link(c, "ddos.output -> int_out.input")

        end

    end
    engine.busywait = opt.busywait
    engine.configure(c)
    engine.main({report = {showlinks=true}})
end

function selftest()
    run({})
end
