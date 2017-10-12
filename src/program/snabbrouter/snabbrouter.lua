-- Multi-process Snabb Router
module(..., package.seeall)

local config     = require("core.config")
local worker     = require("core.worker")
local leader     = require("apps.config.leader")
local follower   = require("apps.config.follower")

local engine     = require("core.app")
local numa       = require("lib.numa")
local yang       = require('lib.yang.yang')

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug

function run(args)
    local graph = config.new()

    local function setup_fn(conf)
       print('Setup FN Called')
       local graph = config.new()
       f(graph, conf, unpack(args))
       return graph
    end


    local cfg_file = args[1] or 'router.conf'
    print('Using config file ' .. cfg_file)
    local conf = yang.load_configuration(cfg_file, { schema_name = 'snabb-router-v1'})

    local processes = 4


    local worker_code = "require('program.snabbrouter.snabbrouter').run_worker(%d)"

    local follower_pids = {}

    for i = 1, processes do
        print('Spawning processs ' .. tostring(i))
        follower_pids[#follower_pids+1] = worker.start("follower", worker_code:format(i))
    end


    config.app(graph, 'leader', leader.Leader, { setup_fn = setup_fn, initial_configuration = conf, follower_pids = follower_pids, schema_name = 'snabb-router-v1' })

    engine.busywait = false
    engine.configure(graph)
    engine.main({report = {showlinks = true}})
end

function selftest()
    run({})
end
