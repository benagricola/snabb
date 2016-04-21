module(..., package.seeall)

local S             = require("syscall")

local app           = require("core.app")
local app_now       = app.now
local datagram      = require("lib.protocol.datagram")
local ethernet      = require("lib.protocol.ethernet")
local ipv4          = require("lib.protocol.ipv4")
local ipv6          = require("lib.protocol.ipv6")
local counter       = require("core.counter")
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
local pf            = require("pf")        -- pflua
local math          = require("math")
local math_max      = math.max
local math_min      = math.min
local math_floor    = math.floor
local math_ceil     = math.ceil
local math_abs      = math.abs
local math_exp      = math.exp
local json          = require("lib.json")
local json_encode   = json.encode
local json_decode   = json.decode

local C = ffi.C
local mask = ffi.C.LINK_RING_SIZE-1

require("core.link_h")


Detector = {}

-- I don't know what I'm doing
function Detector:new (arg)
    local conf = arg and config.parse_app_arg(arg) or {}

    local o = {
        config_file_path = conf.config_file_path,
        config_loaded = 0, -- Last time config was loaded
        last_report   = nil,
        rules         = conf.rules,
        bucket_period = 5,
        ewma_period   = 30,
        core          = conf.core,
    }

    self = setmetatable(o, {__index = Detector})

    self:read_config()


    self.parsed_pps = 0
    self.parsed_bps = 0

    -- datagram object for reuse
    self.d = datagram:new()

    -- schedule periodic task every second
    timer.activate(timer.new(
        "periodic",
        function()
            self:periodic()
        end,
        self.bucket_period * 1e9,
        'repeating'
    ))

    timer.activate(timer.new(
        "report",
        function()
            self:report()
        end,
        1e9,
        'repeating'
    ))

    timer.activate(timer.new(
        "periodic",
        function()
            self:read_config()
        end,
        30 * 1e9,
        'repeating'
    ))

    return self
end

function Detector:read_config()
    local stat = S.stat(self.config_file_path)
    if stat.mtime ~= self.config_loaded then
        local cfg_file = assert(io.open(self.config_file_path, "r"))
        local cfg_raw  = cfg_file:read("*all")
        self.config_loaded = stat.mtime
        local cfg_json = json.decode(cfg_raw)
        self:parse_config(cfg_json)
    end
end

function Detector:parse_config(cfg)
    for rule_num, rule in pairs(cfg.rules) do
        print("Compiling rule '" .. rule.filter .. "'")
        -- compile the filter
        local filter = pf.compile_filter(rule.filter)
        assert(filter)
        rule.cfilter = filter

        -- use default burst value of 2*rate
        if rule.pps_burst_rate == nil and rule.pps_rate then
            rule.pps_burst_rate = 2 * rule.pps_rate
        end
        if rule.bps_burst_rate == nil and rule.bps_rate then
            rule.bps_burst_rate = 2 * rule.bps_rate
        end

        -- Initialise rule-specific counters
        rule.avg_pps = 0
        rule.avg_bps = 0
        rule.pps = 0
        rule.bps = 0
        rule.pps_bucket = 0
        rule.bps_bucket = 0

        rule.last_time  = 0
        rule.in_violation   = false
        rule.first_violated = 0
        rule.last_violated  = 0

        rule.exp_value = math_exp(-self.bucket_period/self.ewma_period)
    end
    self.rule_count = #self.rules
end

function Detector:periodic()
    for rule_num, rule in pairs(self.rules) do
        self:violate_rule(rule)
    end
    io.write(json_encode(self.rules))
    io.flush()
end

function Detector:violate_rule(rule)
    -- Calculate packets / bytes per second over the last bucket
    rule.pps = rule.pps_bucket / self.bucket_period
    rule.bps = rule.bps_bucket / self.bucket_period

    -- Calculate EWMA rate (pps and bps) of packets matching rule
    rule.avg_pps = rule.pps + rule.exp_value * (rule.avg_pps - rule.pps)
    rule.avg_bps = rule.bps + rule.exp_value * (rule.avg_bps - rule.bps)


    local cur_now = tonumber(app_now())

    local violation = false

    -- If rule is violated either in burst or moving average, set the violation type
    if rule.pps_rate then
        if rule.pps > rule.pps_burst_rate then
            violation = 'pps_burst'
        elseif rule.avg_pps > rule.pps_rate then
            violation = "pps"
        end
    end

    if rule.bps_rate then
        if rule.bps > rule.bps_burst_rate then
            violation = "bps_burst"
        elseif rule.bps > rule.bps_rate then
            violation = "bps"
        end
    end


    if violation and not rule.in_violation then
        rule.in_violation   = violation
        rule.first_violated = cur_now
        rule.last_violated  = cur_now
    elseif violation then
        -- If violation type has changed, cancel violation and rescan this rule
        if violation ~= rule.in_violation then
            rule.in_violation = false
            return self:violate_rule(rule)
        end

        rule.last_violated = cur_now
    elseif not violation and rule.in_violation then
        rule.in_violation = false
    end

--    print("["..self.core.."] Rule '" .. rule.filter .. "': " .. rule.pps)

    -- Reset 'burst'
    rule.pps_bucket = 0
    rule.bps_bucket = 0
    self.parsed_pps = 0
    self.parsed_bps = 0
    rule.last_time = cur_now
end


function Detector:push ()
    local i = assert(self.input.input, "input port not found")

    while not link_empty(i) do
        self:process_packet(i)
    end
end


function Detector:process_packet(i)
    local p = link_receive(i)

    -- Parse packet
    -- local d = self.d:new(p, ethernet, {delayed_commit = true})

    -- Check packet against BPF rules
    local rule = self:bpf_match(p)

    self.parsed_pps = self.parsed_pps + 1
    self.parsed_bps = self.parsed_bps + p.length

    -- If packet didn't match a rule, ignore
    if rule == nil then
        -- Free packet
        packet_free(p)
        return
    end

    -- Okay, packet matched - burst into this rule
    rule.pps_bucket = rule.pps_bucket + 1
    rule.bps_bucket = rule.bps_bucket + p.length

    -- TODO: If rule is in violation, log packet?
    -- Free packet
    packet_free(p)
end


function Detector:bpf_match(p)
    local rules = self.rules
    local rule_count = self.rule_count

    for i = 1, rule_count do
        local rule = rules[i]
        if rule.cfilter(p.data, p.length) then
            return rule
        end
    end
    return nil
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


