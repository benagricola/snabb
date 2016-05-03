-- Represents a named bucket, which has a number of defined thresholds,
-- counters tracking current absolute pps and bps rates, and average
-- rates calculated using an exponentially weighted moving average.

module(..., package.seeall)

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local log_debug     = log.debug
local counter       = require("core.counter")
local math          = require("math")
local math_exp      = math.exp
local math_ceil     = math.ceil
local app_now       = require("core.app").now

local Bucket = {
    violations = {
        PPS = 'pps',
        PPS_BURST = 'pps_burst',
        BPS = 'bps',
        BPS_BURST = 'bps_burst',
    },
}

local counter_name = "ddos/%s/%s"

local function open_counter(bucket, metric)
    print("Opening counter: " .. counter_name:format(bucket, metric))
    cnt = counter.open(counter_name:format(bucket, metric))
    return cnt
end

local function close_counter(bucket, metric)
    print("Closing counter: " .. counter_name:format(bucket, metric))
    return counter.delete(counter_name:format(bucket, metric))
end


function Bucket:new(cfg)
    local self = {
        name = cfg.name,
        period         = cfg.period or 1,  -- Buckets are 5s long
        average_period = cfg.avg_period or 30, -- EWMA is calculated over 30s
        pps_burst_rate = cfg.pps_burst_rate,
        bps_burst_rate = cfg.bps_burst_rate,
        pps_rate       = cfg.pps_rate,
        bps_rate       = cfg.bps_rate,
        counters       = {
            pps           = open_counter(cfg.name, 'pps'),
            bps           = open_counter(cfg.name, 'bps'),
            avg_pps       = open_counter(cfg.name, 'avg_pps'),
            avg_bps       = open_counter(cfg.name, 'avg_bps'),
            total_packets = open_counter(cfg.name, 'total_packets'),
            total_bits    = open_counter(cfg.name, 'total_bits'),
        },
        cur_packets    = 0,
        cur_bits       = 0,
        last_update    = app_now(), -- Set so first calculation works
        last_calc      = app_now(), -- Set so first calculation works
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
    log_info([[

      Period: %d
      Average Calc Time: %d
      PPS Threshold: %d/%d (avg/burst)
      BPS Threshold: %d/%d (avg/burst)]],

      self.period,
      self.average_period,
      self.pps_rate or 0,
      self.pps_burst_rate or 0,
      self.bps_rate or 0,
      self.bps_burst_rate or 0)

    return setmetatable(self, {__index = Bucket})
end


function Bucket:add_packet(size)
    self.cur_packets = self.cur_packets + 1
    self.cur_bits    = self.cur_bits + size
end


function Bucket:calculate_rate(now)
    local exp_value = self.exp_value

    -- Calculate time since last calculation time rather than bucket period, this could take
    local last_period = now - self.last_calc

    local pps = math_ceil(self.cur_packets / last_period)
    local bps = math_ceil(self.cur_bits / last_period)

    local avg_pps = pps + exp_value * (self:get_counter('avg_pps') - pps)
    local avg_bps = bps + exp_value * (self:get_counter('avg_bps') - bps)

    self:set_counter('pps', pps)
    self:set_counter('bps', bps)

    self:set_counter('avg_pps', avg_pps)
    self:set_counter('avg_bps', avg_bps)

    -- Add to totals
    self:add_counter('total_packets', self.cur_packets)
    self:add_counter('total_bits', self.cur_bits)

    -- Reset bucket
    self.cur_packets = 0
    self.cur_bits    = 0
    self.last_calc   = now
end

function Bucket:set_counter(name, value)
    local cnt = self.counters[name]
    if not cnt then
        return nil
    end

    counter.set(cnt, value)
    return true
end

function Bucket:add_counter(name, value)
    local cnt = self.counters[name]
    if not cnt then
        return nil
    end

    counter.add(cnt, value)
    return true
end

function Bucket:get_counter(name)
    local cnt = self.counters[name]
    if not cnt then
        return nil
    end

    return tonumber(counter.read(cnt))
end


function Bucket:check_violation(now)
    local violation = false
    local pps = self:get_counter('pps')
    local bps = self:get_counter('bps')
    local avg_pps = self:get_counter('avg_pps')
    local avg_bps = self:get_counter('avg_bps')

    -- If self is violated either in burst or moving average, set the violation type
    if self.bps_rate then
        if bps > self.bps_burst_rate then
            violation = Bucket.violations.BPS_BURST
        elseif avg_bps > self.bps_rate then
            violation = Bucket.violations.BPS
        end
    end

    if self.pps_rate then
        if pps > self.pps_burst_rate then
            violation = Bucket.violations.PPS_BURST
        elseif avg_pps > self.pps_rate then
            violation = Bucket.violations.PPS
        end
    end


    if violation then
        if not self.violated then
            self.first_violated = now
        end

        self.violated = violation
        self.last_violated = now
    elseif self.violated then
        self.violated = false
    end
end

function Bucket:periodic()
    local now = tonumber(app_now())
    -- Only calculate elapsed > self.period
    if (now - self.last_calc) > self.period then
        self:calculate_rate(now)
        self:check_violation(now)
        self.last_calc = now
        self:status()
    end
end

function Bucket:stop()
    -- Delete all registered counters
    for metric, c in pairs(self.counters) do
        close_counter(self.name, metric)
    end
end

function Bucket:status()
    local msg = "%s: %d/%d pps - %d/%d bps - Totals: %d packets / %d Mbits"
    log_debug(msg, self.name, self:get_counter('pps'), self.pps_rate or self.pps_burst_rate or 0, self:get_counter('bps'), self.bps_rate or self.bps_burst_rate or 0, self:get_counter('total_packets'), (self:get_counter('total_bits') / 1024 / 1024))
end

return Bucket
