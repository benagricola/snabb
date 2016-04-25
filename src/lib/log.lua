local app_now = app.now

local _M = {
    _VERSION = "0.01",
}

local function log(msg, level, ...)
    local now = tonumber(app_now())
    local fmt = '[%d] %s: %s'
    print(fmt:format(now, level, msg:format(...)))
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


return _M
