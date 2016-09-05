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
local msgpack        = require("lib.msgpack")
local m_pack         = msgpack.pack
local m_unpack       = msgpack.unpack

local classifier = require("apps.ddos.classifiers.pflua")
local buckets    = require("apps.ddos.lib.buckets")


local struct_counter_t = ffi_typeof('struct counter')

-- Msgpack Monkeypatch to auto-encode cdata counters as an unsigned integer
msgpack.packers['cdata'] = function (buffer, data)
    -- If cdata is a counter, conver to number and encode unsigned
    if ffi_istype(struct_counter_t, data) then
        local num = tonumber(data.c)
        msgpack.packers['unsigned'](buffer, num)
    end
end

require("core.link_h")

Detector = {}


-- I don't know what I'm doing
function Detector:new (arg)
    local conf = arg and config.parse_app_arg(arg) or {}

    local o = {
        config_file_path = conf.config_file_path,
        status_file_path = "/dev/shm/detector-status",
        config_loaded = 0, -- Last time config was loaded
        last_report   = 0,
        last_periodic = 0,
        core          = conf.core,
        classifier    = nil,
        buckets       = nil,
    }

    o.status_temp_path = o.status_file_path .. '-temp'

    self = setmetatable(o, {__index = Detector})

    log_info("Reading initial config...")
    if not self:read_config() then
        log_warn("Could not read config, loading from args..")
        self:parse_config(conf)
    end

    return self
end


function Detector:write_status()
    local status_temp_path = self.status_temp_path
    local status_file_path = self.status_file_path

    -- Write file and then rename into new file
    local status_file = assert(io.open(status_temp_path, "w"))
    local status = {
        buckets       = self.buckets:get_buckets(),
        app_timestamp = app_now(),
        timestamp     = os_time()
    }

    status_file:write(m_pack(status))
    status_file:flush()
    status_file:close()

    -- Rename new file
    if not S.rename(status_temp_path, status_file_path) then
        log_error("Unable to rename detector status file '%s' to '%s'!", status_temp_path, status_file_path)
    end
end


function Detector:read_config()
    if not self.config_file_path then
        return false
    end

    local stat = S.stat(self.config_file_path)
    if stat and stat.isreg then
        if stat.mtime ~= self.config_loaded then
            log_info("Config file '%s' has been modified, reloading...", self.config_file_path)
            local cfg_file = assert(io.open(self.config_file_path, "r"))
            local cfg_raw  = cfg_file:read("*all")
            cfg_file:close()
            self.config_loaded = stat.mtime
            local cfg_json = json_decode(cfg_raw)
            self:parse_config(cfg_json)
            return true
        end
    else
        log_warn("Config file '%s' does not exist, continuing with already-loaded rules...")
        return false
    end
end


function Detector:parse_config(cfg)
    -- Load new instances of bucket and classifier
    self.classifier = classifier:new()
    self.buckets    = buckets:new()

    -- Create rules based on config
    self.classifier:create_rules(cfg.rules)

    -- Create buckets based on config
    self.buckets:create_buckets(cfg.rules)
end


-- Periodic functions here have a resolution of a second or more.
-- Subsecond periodic tasks are not possible
function Detector:periodic()
    local now = app_now()

    -- Return if we havent spent at least a second since the last periodic
    if (now - self.last_periodic) < 1 then
        return
    end

    -- Run classifier and bucket periodic methods
    self.classifier:periodic()
    self.buckets:periodic()

    -- Write status out to file
    self:write_status()

    -- Attempt to reload config if necessary, but do this after logging the last interval data
    self:read_config()
    self.last_periodic = now


    -- Only report if >30s has passed
    if (now - self.last_report) > 30 then
        self:report()
        self.last_report = now
    end
end

function Detector:report()
    -- No-Op right now
end

function Detector:stop()
    log_info("Stop called, calling stop on buckets...")
    self.classifier:stop()
    self.buckets:stop()
end


-- This can be thought of as the application loop
function Detector:push()
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

    -- Run periodic method (TODO: may need moving inside while loop above
    -- if link is too full and doesn't breathe often)
    self:periodic()
end


-- Processes a single received packet. Classify it by defined rules and place
-- into a bucket.
function Detector:process_packet(p)
    local classifier = self.classifier
    local buckets    = self.buckets

    -- Check packet against BPF rules
    local bucket_id = classifier:match(p)

    -- If packet didn't match a rule (no bucket returned), ignore
    if not bucket_id then
        return
    end

    local bucket = buckets:get_bucket_by_id(bucket_id)
    bucket:add_packet(p)

    -- TODO: If rule is in violation, log packet?
    -- TODO: Calculate attacked host or subnet?

    return
end


function selftest ()
    local pcap       = require("apps.pcap.pcap")
    local basic_apps = require("apps.basic.basic_apps")
    local bucket     = require("apps.ddos.lib.bucket")

    local function test_one ()

        -- Generate random data to DDoS app

        local rules = {
            {
                name           = 'ntp',
                filter         = 'udp and src port 123',
                pps_rate       = 100,
                pps_burst_rate = 300,
            },
            {
                name   = 'all',
                filter = '',
                pps_rate       = 1000,
                pps_burst_rate = 3000,
            }
        }

        local c = config.new()

        config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.in")
        config.app(c, "loop", basic_apps.Repeater)
        config.app(c, "detector", Detector, { config_file_path = nil, rules = rules })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> detector.input")
        config.link(c, "detector.output -> sink.input")
        app.configure(c)

        app.main({ duration = 2 })

        local ddos_app = app.app_table.detector
        local ntp_bucket = ddos_app.buckets:get_bucket_by_name('ntp')
        local all_bucket = ddos_app.buckets:get_bucket_by_name('all')


        assert(ntp_bucket and all_bucket, "Could not find created buckets")

        -- Check correct violation type and rates
        assert(ntp_bucket.violated == bucket.violations.PPS_BURST, "Bucket violation type incorrect or not violated")
        assert(ntp_bucket:get_counter('pps') >= ntp_bucket.pps_burst_rate, "Bucket pps less than burst rate")
        assert(all_bucket:get_counter('pps') == 0 and all_bucket:get_counter('bps') == 0 and not all_bucket.violated, "Catchall bucket not zero, packets matched wrong rule!")
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
        config.app(c, "detector", Detector, { config_file_path = nil, rules = rules })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> detector.input")
        config.link(c, "detector.output -> sink.input")
        app.configure(c)

        app.main({ duration = 2 })

        local ddos_app = app.app_table.detector
        local dns_bucket = ddos_app.buckets:get_bucket_by_name('dns')
        local ntp_bucket = ddos_app.buckets:get_bucket_by_name('ntp')

        assert(dns_bucket and ntp_bucket, "Could not find created buckets")


        -- Check correct violation type and rates
        assert(not dns_bucket.violated, "DNS Bucket violated, should not be!")
        assert(dns_bucket:get_counter('bps') == 0, "DNS bucket BPS is not zero")
        assert(ntp_bucket:get_counter('bps') ~= 0 and ntp_bucket:get_counter('bps') > ntp_bucket.bps_burst_rate and ntp_bucket.violated == bucket.violations.BPS_BURST, "Matching bucket recorded no bps, or lower than burst, or not violated")
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
        config.app(c, "detector", Detector, { config_file_path = nil, rules = rules })
        config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.out")

        config.link(c, "source.output -> loop.input")
        config.link(c, "loop.output -> detector.input")
        config.link(c, "detector.output -> sink.input")
        app.configure(c)

        app.main({ duration = 4 })

        local ddos_app = app.app_table.detector
        local dns_bucket = ddos_app.buckets:get_bucket_by_name('rule_53')
        local ntp_bucket = ddos_app.buckets:get_bucket_by_name('rule_123')

        assert(dns_bucket and ntp_bucket, "Could not find created buckets")


        -- Check correct violation type and rates
        assert(not dns_bucket.violated, "DNS Bucket violated, should not be!")
        assert(dns_bucket:get_counter('bps') == 0, "DNS bucket BPS is not zero")
        assert(ntp_bucket:get_counter('bps') ~= 0 and ntp_bucket:get_counter('bps') > ntp_bucket.bps_burst_rate and ntp_bucket.violated ~= nil, "Matching bucket recorded no bps, or lower than burst, or not violated")
    end

    print("DDoS selftest")
    test_one()
    test_two()
    test_three()
    return true
end
