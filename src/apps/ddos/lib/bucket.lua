-- Represents a named bucket, which has a number of defined thresholds,
-- counters tracking current absolute pps and bps rates, and average
-- rates calculated using an exponentially weighted moving average.

module(..., package.seeall)

local log            = require("lib.log")
local log_info       = log.info
local log_warn       = log.warn
local log_error      = log.error
local log_critical   = log.critical
local log_debug      = log.debug
local log_num_prefix = log.num_prefix
local string         = require("string")
local string_rep     = string.rep
local shm            = require("core.shm")
local counter        = require("core.counter")
local math           = require("math")
local math_exp       = math.exp
local math_fmod      = math.fmod
local math_ceil      = math.ceil
local app_now        = require("core.app").now
local SampleSet      = require("apps.ddos.lib.sampler").SampleSet

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
    cnt = counter.open(counter_name:format(bucket, metric))
    return cnt
end

local function close_counter(bucket, metric)
    return counter.delete(counter_name:format(bucket, metric))
end


function Bucket:new(cfg)
    local self = {
        name    = cfg.name,
        filter  = cfg.filter,
        period         = cfg.period or 1,  -- Buckets are 5s long
        average_period = cfg.avg_period or 30, -- EWMA is calculated over 30s
        pps_burst_rate = cfg.pps_burst_rate,
        bps_burst_rate = cfg.bps_burst_rate,
        pps_rate       = cfg.pps_rate,
        bps_rate       = cfg.bps_rate,
        cooldown       = cfg.cooldown or 5, -- Cooldown timer before and after violation to avoid flapping
        sample_rate    = cfg.sample_rate or 1000, -- Sample every 1000 packets when violated, by default
        avg_pps        = 0, -- Used for calculations, counters are integers, this needs to be a float
        avg_bps        = 0, -- Used for calculations, counters are integers, this needs to be a float
        counters       = shm.create_frame(
        "bucket/"..cfg.name,
        {
            pps           = {counter, 0},
            bps           = {counter, 0},
            avg_pps       = {counter, 0},
            avg_bps       = {counter, 0},
            peak_pps      = {counter, 0},
            peak_bps      = {counter, 0},
            total_packets = {counter, 0},
            total_bits    = {counter, 0},
        }),
        cur_packets    = 0,
        cur_bits       = 0,
        last_calc      = app_now(), -- Set so first calculation works
        violated       = false,
        first_violated = 0,
        last_violated  = 0,
        sampler        = nil,
    }

    if self.pps_burst_rate == nil and self.pps_rate then
        self.pps_burst_rate = 2 * self.pps_rate
    end
    if self.bps_burst_rate == nil and self.bps_rate then
        self.bps_burst_rate = 2 * self.bps_rate
    end

    -- Make sure we have a threshold of some sort set
    -- 20/07/16: Not a requirement now, buckets may not be violatable to negatively match traffic
    -- assert(self.pps_burst_rate or self.bps_burst_rate or self.pps_rate or self.bps_rate, "No Threshold rates set for bucket, please set one!")

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


function Bucket:add_packet(packet)
    local sample_rate = self.sample_rate

    local cur_packets = self.cur_packets + 1
    -- Packet.length is bytes
    local cur_bits    = self.cur_bits + (packet.length * 8)

    -- If bucket is violated, sample packet based on desired rate
    if self.violated and math_fmod(cur_packets, sample_rate) == 0 then
        local sampler = self.sampler
        sampler:sample(packet)
    end

    self.cur_packets = cur_packets
    self.cur_bits    = cur_bits
end

function Bucket:calculate_rate(now)
    local exp_value = self.exp_value

    -- Calculate time since last calculation time rather than bucket period, this could take
    local last_period = now - self.last_calc

    local pps = math_ceil(self.cur_packets / last_period)
    local bps = math_ceil(self.cur_bits / last_period)

    self:set_counter('pps', pps)
    self:set_counter('bps', bps)

    local avg_pps = pps + exp_value * (self.avg_pps - pps)
    local avg_bps = bps + exp_value * (self.avg_bps - bps)

    -- log_info("[%s] Avg PPS Calc: %s + %s * (%s - %s) = %s", self.name, tostring(pps), tostring(exp_value), tostring(self:get_counter('avg_pps')), tostring(pps), tostring(avg_pps))
    -- log_info("[%s] Avg BPS Calc: %s + %s * (%s - %s) = %s", self.name, tostring(bps), tostring(exp_value), tostring(self:get_counter('avg_bps')), tostring(bps), tostring(avg_bps))

    self.avg_pps = avg_pps
    self.avg_bps = avg_bps

    self:set_counter('avg_pps', avg_pps)
    self:set_counter('avg_bps', avg_bps)

    -- Calculate peak PPS / BPS
    -- Under normal circumstances this is the peak PPS / BPS since last reset
    -- Peak values are reset when violation state changes
    local peak_pps = self:get_counter('peak_pps')
    local peak_bps = self:get_counter('peak_bps')

    if pps > peak_pps then
        self:set_counter('peak_pps', pps)
    end

    if bps > peak_bps then
        self:set_counter('peak_bps', bps)
    end

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

function Bucket:reset_peak()
    -- Reset peak PPS / BPS
    self:set_counter('peak_pps', 0)
    self:set_counter('peak_bps', 0)
end

function Bucket:check_violation(now)
    local violation = false
    local pps = self:get_counter('pps')
    local bps = self:get_counter('bps')
    local avg_pps = self:get_counter('avg_pps')
    local avg_bps = self:get_counter('avg_bps')

    local cooldown = self.cooldown

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

    local time_since_last_violation = now - (self.last_violated)

    -- Bucket in violation
    if violation then
        -- New violation, check cooldown
        if not self.violated then
            -- Cooldown not expired yet
            if time_since_last_violation < cooldown then
                log_info("Bucket %s violated but still cooling down for %ds", self.name, cooldown - time_since_last_violation)
            -- Cooldown expired, new event
            else
                self.first_violated = now
                self.violated = violation
                self.last_violated = now
                -- Reset peak counters
                self:reset_peak()

                -- Create sampler to store this violation, this overrides old sampler
                self.sampler = SampleSet:new(self)
            end

        -- Ongoing violation
        else
            self.last_violated = now
            self.violated = violation
        end

    -- Bucket not in violation
    else
        -- Ending violation, check cooldown
        if self.violated then
            -- Cooldown not expired yet
            if time_since_last_violation < cooldown then
                log_info("Bucket %s violated but still cooling down for %ds", self.name, cooldown - time_since_last_violation)

            -- Cooldown expired, new event
            else
                self.violated = false
            end
        end
    end
end


function Bucket:packed()
    local counters = {}

    -- Grab counter values as of now
    for counter in pairs(self.counters) do
        counters[counter] = self:get_counter(counter)
    end

    local packed = {
        name           = self.name,
        filter         = self.filter,
        period         = self.period,
        average_period = self.avg_period,
        pps_burst_rate = self.pps_burst_rate,
        bps_burst_rate = self.bps_burst_rate,
        pps_rate       = self.pps_rate,
        bps_rate       = self.bps_rate,
        cooldown       = self.cooldown,
        sample_rate    = self.sample_rate,
        avg_pps        = self.avg_pps,
        avg_bps        = self.avg_bps,
        cur_packets    = self.cur_packets,
        cur_bits       = self.cur_bits,
        last_calc      = self.last_calc,
        violated       = self.violated,
        first_violated = self.first_violated,
        last_violated  = self.last_violated
    }

    if self.sampler then
        packed.sampler = self.sampler:packed()
    end

    return packed
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

local function pad(s, width, padder)
  padder = strrep(padder or " ", abs(width))
  if width < 0 then return strsub(padder .. s, width) end
  return strsub(s .. padder, 1, width)
end

local function rpad(s, width)
    return s .. string_rep(' ', width - #s)
end

local function lpad(s, width)
    return string_rep(' ', width - #s) .. s
end

function Bucket:status()
    -- Check for sampler
    if self.violated and self.sampler then
        self.sampler:status()
    end

    local violated = self.violated or "OK"

    local msg = "%s [%s]: %s/%s pps burst - %s/%s pps avg - %s/%s bps burst - %s/%s bps avg - Totals: %s packets / %s bytes"
    log_info(msg,
        rpad(self.name, 15),
        rpad(violated, 9),
        lpad(log_num_prefix(self:get_counter('pps')), 7),
        rpad(log_num_prefix(self.pps_burst_rate or 0), 7),
        lpad(log_num_prefix(self:get_counter('avg_pps')), 7),
        rpad(log_num_prefix(self.pps_rate or 0), 7),
        lpad(log_num_prefix(self:get_counter('bps')), 7),
        rpad(log_num_prefix(self.bps_burst_rate or 0), 7),
        lpad(log_num_prefix(self:get_counter('avg_bps')), 7),
        rpad(log_num_prefix(self.bps_rate or 0), 7),
        lpad(log_num_prefix(self:get_counter('total_packets')), 7),
        lpad(log_num_prefix(self:get_counter('total_bits')/8), 7)
    )
end

return Bucket
