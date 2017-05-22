local math     = require 'math'
local math_exp = math.exp

local ln2_cst = math.log(2)

local SpaceSaving = {}


local function SimpleRateBucket()
    return {
        key       = "",
        count     = 0,
        lastTs    = 0,
        rate      = 0,
        error     = 0,
        errorTs   = 0,
        errorRate = 0,
    }
end

local function SimpleRate(size, halfLife)
    local out = {
        max = size,
        olist = {},
        hash  = {},
        weightHelper = -ln2_cst / (halfLife * 1e9),
        halfLife = halfLife,
    }

    return out
end

function SpaceSaving:new(size, halfLife)
    local o    = SimpleRate(size, halfLife)
    local self = setmetatable(o, {__index = SpaceSaving})
    return self
end

function SpaceSaving:count(rate, lastTs, nowTs)
    local deltaNs = nowTs - lastTs
    local weight = math_exp(deltaNs * self.weightHelper)

    if deltaNs > 0 and lastTs ~= 0 then
        return rate * weight + (1e9 / deltaNs) * (1 - weight)
    end

    return rate * weight
end

function SpaceSaving:recount(rate, lastTs, nowTs)
    return rate * math_exp((nowTs - lastTs) * self.weightHelper)
end

function SpaceSaving:touch(key, nowTs)
    local olist = self.olist
    local hash  = self.hash
    local max   = self.max
    local bucketno = hash[key]
    local bucket = nil

    if bucketno ~= nil then
        bucket = olist[bucketno]
    else
        local blen = #olist
        if blen < max then
            bucketno = #olist+1

            olist[bucketno] = SimpleRateBucket()
            bucket = olist[bucketno] 

            hash[key] = bucketno

            bucket.key, bucket.errLastTs, bucket.errRate =
                key, bucket.lastTs, bucket.rate
        else
            bucketno = 1
            local cur_bucket = olist[bucketno]

            if hash[cur_bucket.key] then
                hash[cur_bucket.key] = nil
            end

            olist[bucketno] = SimpleRateBucket()
            bucket = olist[bucketno] 

            hash[key] = bucketno

            bucket.key, bucket.errLastTs, bucket.errRate =
                key, bucket.lastTs, bucket.rate
        end

    end

    bucket.count = bucket.count + 1
    if bucket.lastTs ~= 0 then
        bucket.rate = self:count(bucket.rate, bucket.lastTs, nowTs)
    end

    bucket.lastTs = nowTs

    local list_len = #olist

    while true do
        if bucketno == list_len then
            break
        end

        local bucketnext = bucketno + 1

        local b1 = olist[bucketno]
        local b2 = olist[bucketnext]

        if b1.lastTs < b2.lastTs then
            break
        end

        olist[bucketno], olist[bucketnext] = olist[bucketnext], olist[bucketno]
        hash[b1.key] = bucketnext
        hash[b2.key] = bucketno
        bucketno = bucketnext
    end
end

function SpaceSaving:getAll(nowTs)
    local olist = self.olist
    local elements = {}
    for i = #olist, 1, -1 do
        local b = olist[i]
        if b.key ~= "" then
            local rate    = self:recount(b.rate, b.lastTs, nowTs)
            local errRate = self:recount(b.errRate, b.errLastTs, nowTs)
            elements[#elements+1] = {
                Key = b.key,
                LoCount = b.count - b.error,
                HiCount = b.count,
                LoRate  = rate - errRate,
                HiRate  = rate,
            }
        end
    end

    return elements
end

function SpaceSaving:getSingle(key, nowTs)
    local olist = self.olist
    local hash = self.hash
    local bucketno = hash[key]
    local bucket = nil

    if bucketno ~= nil then
        bucket = olist[bucketno]
        local rate    = self:recount(bucket.rate, bucket.lastTs, nowTs)
        local errRate = self:recount(bucket.errRate, bucket.errLastTs, nowTs)
        return rate - errRate, rate
    else
        bucket = olist[1]
        local errRate = self:recount(bucket.rate, bucket.lastTs, nowTs)
        return 0, errRate
    end
        

end


return SpaceSaving
