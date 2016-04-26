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

function PFLua:create_rule(rule)
    log_info("Compiling rule %s with filter '%s'", rule.name, rule.filter)
    local filter = pf.compile_filter(rule.filter)
    assert(filter)
    local rule_count = self.rule_count + 1
    self.rules[rule_count] = filter
    self.rule_count = rule_count
    self.rule_names[rule.name] = rule_count
end

function PFLua:create_rules(rules)
    -- For each input rule
    for rule_num, rule in ipairs(rules) do
        self:create_rule(rule)
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


return PFLua
