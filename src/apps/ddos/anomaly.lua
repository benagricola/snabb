module(..., package.seeall)

local S              = require("syscall")

local app            = require("core.app")
local app_now        = app.now
local log            = require("lib.log")
local log_info       = log.info
local log_warn       = log.warn
local log_error      = log.error
local log_critical   = log.critical
local log_debug      = log.debug
local ffi            = require("ffi")
local ffi_istype     = ffi.istype
local ffi_typeof     = ffi.typeof
local link           = require("core.link")
local link_nreadable = link.nreadable
local link_receive   = link.receive
local link_transmit  = link.transmit
local link_empty     = link.empty
local os             = require("os")
local os_time        = os.time
local io             = require("io")
local io_open        = io.open
local packet         = require("core.packet")
local packet_free    = packet.free
local packet_clone   = packet.clone
local json           = require("lib.json")
local json_decode    = json.decode
local p_ethernet = require("lib.protocol.ethernet")
local p_datagram = require("lib.protocol.datagram")


require("core.link_h")

Anomaly = {
    config = {
        core = { required = false },
    }
}


-- I don't know what I'm doing
function Anomaly:new (conf)

    local o = {
        last_report   = 0,
        last_periodic = 0,
        core          = conf.core or 0,
    }

    self = setmetatable(o, {__index = Anomaly})

    return self
end


-- Periodic functions here have a resolution of a second or more.
-- Subsecond periodic tasks are not possible
function Anomaly:periodic()
    local now = app_now()

    -- Return if we havent spent at least a second since the last periodic
    if (now - self.last_periodic) < 1 then
        return
    end

    self.last_periodic = now


    -- Only report if >30s has passed
    if (now - self.last_report) > 5 then
        self:report()
        self.last_report = now
    end
end


function Anomaly:report()
    -- No-Op right now
end


function Anomaly:stop()
end


-- This can be thought of as the application loop
function Anomaly:push()
    local input  = self.input
    local output = self.output.output

    for _, l in ipairs(input) do
        for _ = 1, link_nreadable(l) do
            -- Receive packet
            local p = link_receive(l)

            self:process_packet(p)

            -- Forward packet to any output interfaces
            if output then
                link_transmit(output, packet_clone(p))
            end

            -- Free packet
            packet_free(p)
        end
    end

    -- Run periodic method
    self:periodic()
end


-- Processes a single received packet. Classify it by defined rules and place
-- into a bucket.
function Anomaly:process_packet(p)
    local dgram = p_datagram(p, p_ethernet)

    print(dgram:parse():type())
    return
end


function selftest ()
    local pcap       = require("apps.pcap.pcap")
    local basic_apps = require("apps.basic.basic_apps")
    local bucket     = require("apps.ddos.lib.bucket")

    local function test_one ()

        -- Generate random data to DDoS app

        local c = config.new()

        config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.in")
        config.app(c, "loop", basic_apps.Repeater)
        config.app(c, "anomaly", Anomaly, { })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> anomaly.input")
        config.link(c, "anomaly.output -> sink.input")
        app.configure(c)

        app.main({ duration = 2 })

    end

    local function test_two ()
        local rules = {
            {
                name           = 'dns',
                filter         = 'udp and port 53',
                bps_rate       = 100,
                bps_burst_rate = 300,
            },

            {
                name           = 'ntp',
                filter         = 'udp and src port 123',
                bps_rate       = 100,
                bps_burst_rate = 300,
            },
        }

        local c = config.new()

        config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.in")
        config.app(c, "loop", basic_apps.Repeater)
        config.app(c, "anomaly", Anomaly, { config_file_path = nil, rules = rules })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> anomaly.input")
        config.link(c, "anomaly.output -> sink.input")
        app.configure(c)

        app.main({ duration = 2 })

        local anomaly_app = app.app_table.anomaly
    end

    local function test_three ()
        local rules = {}

        -- Create 1000 rules
        for i = 1, 1000 do
            local rule_name = "rule_%d"
            local rule_filter = "udp and src port %d"

            rules[i] = {
                name = rule_name:format(i),
                filter = rule_filter:format(i),
                pps_rate = 100,
                bps_rate = 100,
                pps_burst_rate = 200,
                bps_burst_rate = 200,
            }
        end

        local c = config.new()

        config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.in")
        config.app(c, "loop", basic_apps.Repeater)
        config.app(c, "anomaly", Anomaly, { config_file_path = nil, rules = rules })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> anomaly.input")
        config.link(c, "anomaly.output -> sink.input")
        app.configure(c)

        app.main({ duration = 4 })

        local anomaly_app = app.app_table.anomaly
    end

    test_one()
    test_two()
    test_three()
    return true
end
