local app_now = require("core.app").now
local string_format = require("string").format

local _M = {}


local function log(msg, level, ...)
    local now = tonumber(app_now())
    local fmt = '[%d] %s: %s'
    print(string_format(fmt, now, level, string_format(msg, ...)))
end

function _M.info(msg, ...)
    log(msg, 'INFO', ...)
end

function _M.warn(msg, ...)
    log(msg, 'WARN', ...)
end

function _M.error(msg, ...)
    log(msg, 'ERROR', ...)
end

function _M.critical(msg, ...)
    log(msg, 'CRITICAL', ...)
end

function _M.debug(msg, ...)
    log(msg, 'DEBUG', ...)
end

function _M.num_prefix(num)
    if num > 1e12 then
        return string_format("%0.2fT", num / 1e12)
    end
    if num > 1e9 then
        return string_format("%0.2fG", num / 1e9)
    end
    if num > 1e6 then
        return string_format("%0.2fM", num / 1e6)
    end
    if num > 1e3 then
        return string_format("%0.2fk", num / 1e3)
    end
    return string_format("%0.2f", num)
end

function _M.print_r ( t )
    local print_r_cache={}
    local function sub_print_r(t,indent)
        if (print_r_cache[tostring(t)]) then
            print(indent.."*"..tostring(t))
        else
            print_r_cache[tostring(t)]=true
            if (type(t)=="table") then
                for pos,val in pairs(t) do
                    if (type(val)=="table") then
                        print(indent.."["..pos.."] => "..tostring(t).." {")
                        sub_print_r(val,indent..string.rep(" ",string.len(pos)+8))
                        print(indent..string.rep(" ",string.len(pos)+6).."}")
                    elseif (type(val)=="string") then
                        print(indent.."["..pos..'] => "'..val..'"')
                    else
                        print(indent.."["..pos.."] => "..tostring(val))
                    end
                end
            else
                print(indent..tostring(t))
            end
        end
    end
    if (type(t)=="table") then
        print(tostring(t).." {")
        sub_print_r(t,"  ")
        print("}")
    else
        sub_print_r(t,"  ")
    end
    print()
end


return _M
