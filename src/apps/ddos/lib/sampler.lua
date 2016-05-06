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
local math_exp      = math.exp
local math_fmod     = math.fmod
local math_ceil     = math.ceil
local app_now       = require("core.app").now
local ffi           = require("ffi")
local ffi_cast      = ffi.cast
local ffi_typeof    = ffi.typeof

local rd16, wr16, rd32, wr32 = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.wr32

local n_ethertype_ipv4     = constants.n_ethertype_ipv4
local n_ethertype_ipv6     = constants.n_ethertype_ipv6
local o_ethernet_ethertype = constants.o_ethernet_ethertype
local o_ipv4_proto         = constants.o_ipv4_proto
local ethernet_header_size = constants.ethernet_header_size

local afi = {
    ipv4 = 'ipv4',
    ipv6 = 'ipv6',
}

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
        values      = {},
        value_names = {},
        top_value   = nil,
        total       = 0,
    }

    return setmetatable(self, {__index = Sample})
end


function Sample:value(value, count)
    if not value then
        log_error("Tried to sample a nil value!")
        return
    end

    local count = count or 1 -- Default count to 1

    local value_names = self.value_names
    local values = self.values
    local val_length = #values + 1

    local val_index

    if not value_names[value] then

        -- Do not create more unique values if we're already tracking more than 'limit' discrete values
        if val_length > self.limit then
            log_warn("Unable to create new value '%s', limit %d reached", tostring(value), self.limit)
            return false
        end

        value_names[value] = val_length
        val_index = val_length
    else
        val_index = value_names[value]
    end

    local new_value = (values[val_index] or 0) + count

    values[val_index] = new_value

    self.total = self.total + count
    local ratio = new_value / self.total

    -- If over x% (as ratio of 0-1) is a single type, identify that type as our 'current' value
    if ratio >= self.certainty then
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
        started            = app_now(),
        finished           = 0,
        sampled_packets    = 0, -- Note - this is total packets *sampled*, multiply by sample rate for approximate total packet count
        sampled_bits       = 0, -- Note - this is total bits *sampled*, multiply by sample rate for approximate total bit count

        avg_size           = 0,
        min_size           = 0,
        max_size           = 0,

        invalid_length     = 0,
        invalid_version    = 0,
        fragment           = 0,

        afi                = Sample:new(0.8, 3), -- Certainty of 0.8, limit of 3 discrete values - we only track IPv4, IPv6 and ARP.
        protocol           = Sample:new(0.8, 142), -- Currently 142 'known' IP protocols

        tcp_flags          = Sample:new(0.8, 9), -- 9 Possible TCP flags
        src_hosts          = Sample:new(0.8, 1000), -- Limit to 1000 possible Source IPs
        src_subnets        = Sample:new(0.8, 100),  -- Limit to 100 possible Source Subnets
        src_ports          = Sample:new(0.8, 1000), -- Limit to 1000 possible Source Ports
        dst_hosts          = Sample:new(0.8, 1000), -- Limit to 1000 possible Destination IPs
        dst_subnets        = Sample:new(0.8, 100),  -- Limit to 100 possible Destination Subnets
        dst_ports          = Sample:new(0.8, 1000), -- Limit to 1000 possible Destination Ports
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
    self.avg_size = self.sampled_bits / self.sampled_packets

    if packet_length > self.max_size then
        self.max_size = packet_length
    elseif packet_length < self.min_size then
        self.min_size = packet_length
    end


    local p_data = packet.data(p)

    local ethertype = rd16(p_data + o_ethernet_ethertype)

    -- If IPv4 packet, parse as such
    if ethertype == n_ethertype_ipv4 then
        p_data = p_data + ethernet_header_size

        self.afi:value(afi.ipv4) -- Add '1' to incidence of ipv4 traffic

        -- Parse IPv4 Protocol
        local proto = p_data + o_ipv4_proto
        self.protocol:value(tonumber(proto))


    -- elseif ethertype == ethertype_ipv6 then

    else
        log_error("Attempted to sample packet with unsupported ethertype %d", tonumber(ethertype))
        return false
    end
    self.finished = app_now()
end
