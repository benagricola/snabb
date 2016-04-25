-- Represents a named bucket, which has a number of defined thresholds,
-- counters tracking current absolute pps and bps rates, and average
-- rates calculated using an exponentially weighted moving average.

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local math_exp      = require("math").exp
local app_now       = require("core.app").now

local _M = {
    _VERSION = "0.01",
}

local mt = { __index = _M }


function _M.new(cfg)
    local self = {
        name = cfg.name,
        period         = cfg.period or 5,  -- Buckets are 5s long
        average_period = cfg.period or 30, -- EWMA is calculated over 30s
        pps_burst_rate = cfg.pps_burst_rate,
        bps_burst_rate = cfg.bps_burst_rate,
        pps_rate       = cfg.pps_rate,
        bps_rate       = cfg.bps_rate,
        pps            = 0,
        bps            = 0,
        avg_pps        = 0,
        avg_bps        = 0,
        cur_packets    = 0,
        cur_bits       = 0,
        total_packets  = 0,
        total_bits     = 0,
        last_update    = 0,
        last_calc      = 0,
        violated       = false,
        first_violated = 0,
        last_violated  = 0
    }

    if self.pps_burst_rate == nil and self.pps_rate then
        self.pps_burst_rate = 2 * self.pps_rate
    end
    if self.bps_burst_rate == nil and self.bps_rate then
        self.bps_burst_rate = 2 * self.bps_rate
    end

    -- Make sure we have a threshold of some sort set
    assert(self.pps_burst_rate or self.bps_burst_rate or self.pps_rate or self.bps_rate, "No Threshold rates set for bucket, please set one!")

    -- Calculate Exponent value for EWMA
    self.exp_value = math_exp(-self.period/self.average_period)

    log_info("Initialised bucket '%s' with settings:", self.name)
    log_info("Period: %d\nAverage Calc Time: %d\nPPS Rate: %d/%d (avg/burst)\nBPS Rate: %d/%d (avg/burst)", self.period, self.average_period, self.pps_rate, self.pps_burst_rate, self.bps_rate, self.bps_burst_rate)

    return setmetatable(self, mt)
end


function _M.add_packet(self,size)
    self.cur_packets = self.cur_packets+1
    self.cur_bits    = self.cur_bits + size
end


function _M.calculate_rate(self)
    local exp_value = self.exp_value
    local pps = self.pps
    local bps = self.bps

    local now = tonumber(app_now())
    -- Calculate time since last calculation time :)
    local last_period = now - self.last_calc

    -- Calculate packets / bytes per second since the last calculation
    self.pps = self.cur_packets / last_period
    self.bps = self.cur_bits / last_period

    -- Calculate EWMA rate (pps and bps)
    self.avg_pps = pps + exp_value * (self.avg_pps - pps)
    self.avg_bps = bps + exp_value * (self.avg_bps - bps)

    -- Reset bucket
    self.cur_packets = 0
    self.cur_bits    = 0
    self.last_calc   = now
end

function _M.check_violation(self)
    local now = app_now()
    local violation = false
    local pps = self.pps
    local bps = self.bps

    -- If self is violated either in burst or moving average, set the violation type
    if self.bps_rate then
        if bps > self.bps_burst_rate then
            violation = "bps_burst"
        elseif avg_bps > self.bps_rate then
            violation = "bps"
        end
    end

    if self.pps_rate then
        if pps > self.pps_burst_rate then
            violation = 'pps_burst'
        elseif self.avg_pps > self.pps_rate then
            violation = "pps"
        end
    end


    if not self.violated then
        self.first_violated = now
    end

    if violation then
        self.violated = violation
        self.last_violated = now
    elseif self.violated then
        self.violated = false
    end
end

function _M.periodic(self)
    local now = app_now()

    if now - self.last_calc > self.period then
        self:calculate_rate()
        self:check_violation()
        self.last_calc = now
    end
end

function _M.debug(self)
    local msg = [[ Bucket %s:
        Period: %d
        Average Period: %d
        PPS: %d/%d (cur/avg)
        PPS Threshold: %d/d (burst/avg)
        BPS: %d/%d (cur/avg)
        BPS Threshold: %d/d (burst/avg)
        Totals: %d/%d (packets/bits)
        Last Update: %d
        Last Rate Calculation: %d
        Violated: %s
        First Violated: %d
        Last Violated: %d ]]

    log_debug(msg, self.period, self.average_period,
        self.pps, self.avg_pps, self.pps_burst_rate,
        self.pps_rate, self.bps, self.avg_bps,
        self.bps_burst_rate, self.bps_rate, self.total_packets,
        self.total_bits, self.last_update, self.last_calc,
        self.violated, self.first_violated,uself.last_violated)

end

return _M
