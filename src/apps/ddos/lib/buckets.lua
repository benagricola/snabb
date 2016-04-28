-- Represents a set of buckets.
-- Allows creation of buckets and retrieval by id or name
module(..., package.seeall)

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local bucket        = require("apps.ddos.lib.bucket")
local app_now       = require("core.app").now

local Buckets = {}

function Buckets:new(cfg)
    local self = {
        buckets      = {},
        bucket_names = {},
        bucket_count = 0,
    }

    return setmetatable(self, {__index = Buckets})
end


function Buckets:create_bucket(cfg)
    local buckets = self.buckets
    local new_bucket = bucket:new(cfg)
    local bucket_count = self.bucket_count+1
    buckets[bucket_count] = new_bucket
    self.bucket_count = bucket_count
    self.bucket_names[cfg.name] = bucket_count
    return new_bucket
end

function Buckets:periodic()
    local bucket_count = self.bucket_count
    local buckets = self.buckets
    local start = app_now()
    -- For each bucket
    for i = 1, bucket_count do
        buckets[i]:periodic()
    end
    log_info("Periodic took %ds", app_now() - start)
end

-- Class method to create buckets
function Buckets:create_buckets(rules)
    local buckets = {}
    for rule_num, rule in ipairs(rules) do
        self:create_bucket(rule)
    end
end

function Buckets:get_bucket_by_id(bucket_id)
    return self.buckets[bucket_id]
end

function Buckets:get_bucket_by_name(bucket_name)
    local bucket_id = self.bucket_names[bucket_name]

    if not bucket_id then
        return nil
    end

    return self.buckets[bucket_id]
end

function Buckets:get_buckets()
    return self.buckets
end

function Buckets:stop()
    -- Stop all buckets (e.g. close shared memory)
    local bucket_count = self.bucket_count
    local buckets = self.buckets
    -- For each bucket
    for i = 1, bucket_count do
        buckets[i]:stop()
    end
end

return Buckets
