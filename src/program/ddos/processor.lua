local link_num   = tonumber(main.parameters[1]) or 1 -- Default read from link 1, no multiprocessing benefits
local rules      = main.parameters[2] or "" -- Default empty config, no rules
local core       = tonumber(main.parameters[3])

local S          = require("syscall")
-- Bind to a core
S.sched_setaffinity(nil, {core})

local json_decode = require("lib.json").decode
local receive     = require("apps.inter_proc.receive")
local ddos        = require("apps.dosprotect.dosprotect")

local rules = json_decode(rules)

assert(rules,"JSON Rules input not valid")

local c = config.new()

local conf = {
    rules     = rules,
    core      = core,
}

config.app(c, "dosprotect", ddos.DoSProtect, conf)
print("Receiving from ddostop_".. link_num)

config.app(c, "receive", receive, {linkname='ddostop_' .. link_num})

config.link(c, "receive.output -> dosprotect.input")

engine.busywait = true
engine.configure(c)
engine.main({report = {showlinks=true, showapps=true}})
