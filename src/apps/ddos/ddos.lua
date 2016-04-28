module(..., package.seeall)

local S             = require("syscall")

local app           = require("core.app")
local app_now       = app.now
local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug
local datagram      = require("lib.protocol.datagram")
local ethernet      = require("lib.protocol.ethernet")
local ipv4          = require("lib.protocol.ipv4")
local ipv6          = require("lib.protocol.ipv6")
local counter       = require("core.counter")
local shm           = require("core.shm")
local ffi           = require("ffi")
local link          = require("core.link")
local link_receive  = link.receive
local link_empty    = link.empty
local link_transmit = link.transmit
local link_receive  = link.receive
local link_nreadable = link.nreadable
local link_nwritable = link.nwritable
local link_receive  = link.receive
local packet        = require("core.packet")
local packet_free   = packet.free
local packet_clone  = packet.clone
local math          = require("math")
local math_max      = math.max
local math_min      = math.min
local math_floor    = math.floor
local math_ceil     = math.ceil
local math_abs      = math.abs
local math_exp      = math.exp
local json          = require("lib.json")
local json_decode   = json.decode
local msgpack       = require("lib.msgpack")
local m_pack        = msgpack.pack
local m_unpack      = msgpack.unpack

msgpack.packers['cdata'] = function (buffer, data)
    -- If cdata is a counter, conver to number and encode unsigned
    if ffi.istype("struct counter", data) then
        local num = tonumber(data.c)
        msgpack.packers['unsigned'](buffer, num)
    end
end

local C = ffi.C
local mask = ffi.C.LINK_RING_SIZE-1

require("core.link_h")

Detector = {}


-- I don't know what I'm doing
function Detector:new (arg)
    local conf = arg and config.parse_app_arg(arg) or {}

    local classifier = require("apps.ddos.classifiers.pflua")
    local buckets    = require("apps.ddos.lib.buckets")

    local o = {
        config_file_path = conf.config_file_path,
        status_file_path = "/dev/shm/detector-status",
        config_loaded = 0, -- Last time config was loaded
        last_report   = 0,
        last_periodic = 0,
        core          = conf.core,
        classifier    = classifier:new(),
        buckets       = buckets:new(),
    }

    self = setmetatable(o, {__index = Detector})

    log_info("Reading initial config...")
    if not self:read_config() then
        log_warn("Could not read config, loading from args..")
        self:parse_config(conf)
    end

    -- datagram object for reuse
    self.d = datagram:new()

    return self
end


function Detector:write_status()
    local status_file = assert(io.open(self.status_file_path, "w"))
    status_file:write(m_pack(self.buckets:get_buckets()))
    status_file:close()
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


-- This can be thought of as the application loop
function Detector:push()
    local i = assert(self.input.input, "input port not found")

    -- While link is not empty
    while not link_empty(i) do
        -- Process packet
        self:process_packet(i)
    end

    -- Run periodic method (TODO: may need moving inside while loop above
    -- if link is too full and doesn't breathe often)
    self:periodic()
end

-- Processes a single received packet. Classify it by defined rules and place
-- into a bucket.
function Detector:process_packet(i)
    local classifier = self.classifier
    local buckets    = self.buckets

    -- Parse packet
    local p          = link_receive(i)

    -- local d = self.d:new(p, ethernet, {delayed_commit = true})

    -- Check packet against BPF rules

    local bucket_id = classifier:match(p)

    -- If packet didn't match a rule (no bucket returned), ignore
    if bucket_id == nil then
        -- Free packet
        packet_free(p)
        return
    end

    local bucket = buckets:get_bucket_by_id(bucket_id)
    bucket:add_packet(p.length)

    -- TODO: If rule is in violation, log packet?

    -- Free packet
    packet_free(p)
end



function Detector:print_packet(d)
    -- Top of the stack is 'ethernet'
    -- Next down is AFI, ipv4/ipv6
    local ethernet  = d:parse()
    local ip_hdr    = d:parse()

    local src, dst

    local ethernet_type = ethernet:type()

    local afi

    if ethernet_type == 0x0800 then
        src = ipv4:ntop(ip_hdr:src())
        dst = ipv4:ntop(ip_hdr:dst())
        afi = 'ipv4'
    elseif ethernet_type == 0x86dd then
        src = ipv6:ntop(ip_hdr:src())
        dst = ipv6:ntop(ip_hdr:dst())
        afi = 'ipv6'
    end

    local proto_type = ip_hdr:protocol()

    local proto_hdr = d:parse()

    local src_port = proto_hdr:src_port()
    local dst_port = proto_hdr:dst_port()


    print(table.concat({
        afi,
        " Packet, proto ",
        tostring(proto_type),
        " ",
        src,
        ':',
        src_port,
        ' -> ',
        dst,
        ':',
        dst_port,
        ' matched filter: ',
        rule.filter}
    ))
end


function Detector:get_stats_snapshot()
    return link.stats(self.input.input)
end


function Detector:report()
    if self.last_stats == nil then
        self.last_stats = self:get_stats_snapshot()
        return
    end
    last = self.last_stats
    cur = self:get_stats_snapshot()

    self.last_stats = cur
end

function selftest ()
    print("DDoS selftest")

    local pcap       = require("apps.pcap.pcap")
    local basic_apps = require("apps.basic.basic_apps")
    local bucket     = require("apps.ddos.lib.bucket")

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
    log.print_r(ddos_app.buckets.bucket_names)
    local dns_bucket = ddos_app.buckets:get_bucket_by_name('dns')
    local ntp_bucket = ddos_app.buckets:get_bucket_by_name('ntp')

    assert(dns_bucket and ntp_bucket, "Could not find created buckets")


    -- Check correct violation type and rates
    assert(not dns_bucket.violated, "DNS Bucket violated, should not be!")
    assert(dns_bucket:get_counter('bps') == 0, "DNS bucket BPS is not zero")
    assert(ntp_bucket:get_counter('bps') ~= 0 and ntp_bucket:get_counter('bps') > ntp_bucket.bps_burst_rate and ntp_bucket.violated == bucket.violations.BPS_BURST, "Matching bucket recorded no bps, or lower than burst, or not violated")

    return true
end
