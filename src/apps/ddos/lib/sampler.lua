module(..., package.seeall)

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug
local constants     = require("apps.lwaftr.constants")
local lwutil        = require("apps.lwaftr.lwutil")
local counter       = require("core.counter")
local packet        = require("core.packet")
local math          = require("math")
local ipv4          = require("lib.protocol.ipv4")
local ntop          = ipv4.ntop
local pton          = ipv4.pton
local math_exp      = math.exp
local math_fmod     = math.fmod
local math_ceil     = math.ceil
local app_now       = require("core.app").now
local ffi           = require("ffi")
local bit           = require("bit")
local bit_band      = bit.band
local ffi_cast      = ffi.cast
local ffi_typeof    = ffi.typeof

local rd16, wr16, rd32, wr32 = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.wr32
local ntohs, ntohl = lwutil.htons, lwutil.htonl

local n_ethertype_ipv4     = constants.n_ethertype_ipv4
local n_ethertype_ipv6     = constants.n_ethertype_ipv6
local o_ethernet_ethertype = constants.o_ethernet_ethertype
local o_ipv4_ver_and_ihl   = constants.o_ipv4_ver_and_ihl
local o_ipv4_proto         = constants.o_ipv4_proto
local o_ipv4_total_length  = constants.o_ipv4_total_length
local o_ipv4_src_addr      = constants.o_ipv4_src_addr
local o_ipv4_dst_addr      = constants.o_ipv4_dst_addr
local ethernet_header_size = constants.ethernet_header_size


local afi = {
    ipv4    = 'ipv4',
    ipv6    = 'ipv6',
    invalid = 'invalid',
}

-- /24 as hex mask
local subnet_mask = 0xFFFFFF00

local function get_ethernet_payload(p)
    return p.data + ethernet_header_size
end


local function get_ethertype(p)
    return rd16(p.data + o_ethernet_ethertype)
end


local function get_ipv4_version(p)
    local byte = p[o_ipv4_ver_and_ihl]
    return bit_band(byte, 0xF0) / 4
end


local function get_ipv4_ihl(p)
    local byte = p[o_ipv4_ver_and_ihl]
    return bit_band(byte, 0x0F) * 4
end


local function get_ipv4_total_length(p)
    return ntohs(rd16(p + o_ipv4_total_length))
end


local function get_ipv4_proto(p)
    return p[o_ipv4_proto]
end

local function get_ipv4_src(p)
    print(rd32(p + o_ipv4_src_addr))
    return rd32(p + o_ipv4_src_addr)
end

local function get_ipv4_dst(p)
    return rd32(p + o_ipv4_dst_addr)
end

local function get_subnet_from_ip(ip)
    return bit_band(ip, subnet_mask)
end

-- Represents a sample of discrete values, tracking a count for each value and a total.
-- Limits to the number of discrete values can be added
local Sample = {}

function Sample:new(certainty, limit)
    if certainty <= 0.5 then
        log_error("Certainty must be greater than 0.5 otherwise we cant calculate the majority of traffic!")
        return
    end

    local self = {
        certainty   = certainty,
        limit       = limit or 100, -- Default to 100 discrete values per sample
        value_count = 0,
        values      = {},
        value_names = {},
        top_value   = nil,
        total       = 0,
    }

    return setmetatable(self, {__index = Sample})
end


function Sample:value(value, count)
    -- False is a valid value!
    if value == nil then
        log_error("Tried to sample a nil value!")
        return
    end

    local count = count or 1 -- Default count to 1

    local value_names = self.value_names
    local values = self.values

    local certainty = self.certainty

    local val_index

    if not value_names[value] then
        local val_length = #values + 1

        -- Do not create more unique values if we're already tracking more than 'limit' discrete values
        if val_length > self.limit then
            log_debug("Unable to create new value '%s', limit %d reached", tostring(value), self.limit)
            return false
        end

        value_names[value] = val_length
        val_index = val_length
        self.value_count = val_length
    else
        val_index = value_names[value]
    end

    local new_value = (values[val_index] or 0) + count

    values[val_index] = new_value

    self.total = self.total + count
    local ratio = new_value / self.total

    -- If over x% (as ratio of 0-1) is a single type, identify that type as our 'current' value
    if ratio >= certainty then
        self.top_value = { value, ratio, new_value } -- Value name, ratio compared to total, current value
    else
        self.top_value = nil
    end

    return true
end


function Sample:get(value)
    local value_names = self.value_names
    local values = self.values
    local total = self.total
    local val_index = value_names[value]
    if val_index then
        return {
            values[val_index],          -- Total count for this value
            (values[val_index] / total) -- Ratio of this value to total
        }
    end
end


function Sample:get_top()
    local top_value = self.top_value
    if not top_value then
        return nil
    end
    return top_value
end



SampleSet = {}

function SampleSet:new(cfg)
    local self = {
        name               = cfg.name or "Unknown Sample Set",
        started            = app_now(),
        finished           = 0,
        sampled_packets    = 0, -- Note - this is total packets *sampled*, multiply by sample rate for approximate total packet count
        sampled_bits       = 0, -- Note - this is total bits *sampled*, multiply by sample rate for approximate total bit count

        sampled_duration   = 0,
        subnet_mask        = subnet_mask, -- Store subnet mask for use by consuming applications
        avg_packet_size    = 0,
        min_packet_size    = 0,
        max_packet_size    = 0,

        invalid_ip_version = Sample:new(cfg.invalid_ip_version_certainty or 0.8, 2), -- Limit to 2 discrete values - true and false!
        invalid_ip_length  = Sample:new(cfg.invalid_ip_length_certainty or 0.8, 2), -- Limit to 2 discrete values - true and false!
        fragment           = 0,

        afi                = Sample:new(cfg.afi_certainty or 0.8, 3), -- Certainty of 0.8, limit of 3 discrete values - we only track IPv4, IPv6 and ARP.
        protocol           = Sample:new(cfg.protocol_certainty or 0.8, 142), -- Currently 142 'known' IP protocols

        tcp_flags          = Sample:new(cfg.tcp_flags_certainty or 0.8, 9), -- 9 Possible TCP flags
        src_hosts          = Sample:new(cfg.src_hosts or 0.8, cfg.src_hosts_limit or 1000), -- Limit to 1000 possible Source IPs
        src_subnets        = Sample:new(cfg.src_subnets or 0.8, cfg.src_subnets_limit or 100),  -- Limit to 100 possible Source Subnets
        src_ports          = Sample:new(cfg.src_ports or 0.8, cfg.src_ports_limit or 1000), -- Limit to 1000 possible Source Ports
        dst_hosts          = Sample:new(cfg.dst_hosts or 0.8, cfg.dst_hosts_limit or 1000), -- Limit to 1000 possible Destination IPs
        dst_subnets        = Sample:new(cfg.dst_subnets or 0.8, cfg.dst_subnets_limit or 100),  -- Limit to 100 possible Destination Subnets
        dst_ports          = Sample:new(cfg.dst_ports or 0.8, cfg.dst_ports_limit or 1000), -- Limit to 1000 possible Destination Ports
        data               = {},
    }

    return setmetatable(self, {__index = SampleSet})
end


function SampleSet:sample(p)
    self.sampled_packets = self.sampled_packets + 1

    local packet_length = p.length
    self.sampled_bits = self.sampled_bits + packet_length

    -- Average size of packets across whole sample set
    -- TODO: Moving average over reduced number of samples may make more sense in practice
    -- avg -= avg / N;
    -- avg += new_sample / N;
    self.avg_packet_size = self.sampled_bits / self.sampled_packets

    if packet_length > self.max_packet_size then
        self.max_packet_size = packet_length
    elseif packet_length < self.min_packet_size then
        self.min_packet_size = packet_length
    end

    local received_length = p.length
    local ethertype       = get_ethertype(p)
    local e_payload       = get_ethernet_payload(p)

    local valid_ip_version = false
    local valid_ip_length  = false

    -- If IPv4 packet, parse as such
    if ethertype == n_ethertype_ipv4 then
        self.afi:value(afi.ipv4) -- Add '1' to incidence of ipv4 traffic

        -- Check valid version
        local h_version = get_ipv4_version(e_payload)
        valid_ip_version = h_version == 4

        -- Check received data > 60 and matches length in IP Header
        local expected_length = get_ipv4_total_length(e_payload)
        valid_ip_length = (expected_length + ethernet_header_size) ~= received_length and received_length > 60

        -- Parse IPv4 Protocol
        local proto = get_ipv4_proto(e_payload)
        self.protocol:value(tonumber(proto))

        -- Parse src and dst addresses
        local src_ip = get_ipv4_src(e_payload)
        self.src_hosts:value(src_ip)

        local dst_ip = get_ipv4_dst(e_payload)
        self.dst_hosts:value(dst_ip)

        -- Parse src and dst subnets based on a mask
        local src_subnet = get_subnet_from_ip(src_ip)
        local dst_subnet = get_subnet_from_ip(dst_ip)

        self.src_subnets:value(src_subnet)
        self.dst_subnets:value(dst_subnet)

    -- elseif ethertype == ethertype_ipv6 then
        --self.afi:value(afi.ipv6)

    else
        self.afi:value(afi.invalid)
        log_error("Attempted to sample packet with unsupported ethertype %d", tonumber(ethertype))
    end

    self.invalid_ip_length:value(valid_ip_length)
    self.invalid_ip_version:value(valid_ip_version)
    self.finished = app_now()
    self.sampled_duration = self.finished - self.started
end


function SampleSet:status()
    log_debug("SampleSet Status")
end

function SampleSet:finish()
    self.finished = app_now()
end
