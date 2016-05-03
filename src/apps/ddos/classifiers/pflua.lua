module(..., package.seeall)

local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical

local pf            = require("pf")

local PFLua = {}

function PFLua:new(rules)
    local o = {
        rules      = {},
        rule_names = {},
        rule_count = 0
    }

    self = setmetatable(o, {__index = PFLua})
    return self
end

function PFLua:create_rule(rule, index)
    local rules = self.rules

    -- Delete old rule name ref before overwriting
    if rules[index] then
        self.rule_names:remove(rules[index].name)
    end

    local filter = pf.compile_filter(rule.filter)
    assert(filter)
    rules[index] = filter
    self.rule_count = #rules
    self.rule_names[rule.name] = index
end

function PFLua:create_rules(rules)
    -- For each input rule
    for rule_num, rule in ipairs(rules) do
        self:create_rule(rule, rule_num)
    end
end

function PFLua:match(packet)
    local rules = self.rules
    local rule_count = self.rule_count

    -- For each rule
    for i = 1, rule_count do
        local rule = rules[i]
        -- Check if rule matches against packet data and length
        if rule(packet.data, packet.length) then
            -- Return rule id if match
            return i
        end
    end
    -- Otherwise return nothing
    return nil
end

function PFLua:periodic()
    -- No Op
end

function PFLua:stop()
    -- No Op
end


return PFLua
