-- Represents a Zebra Message
local constants = require('apps.lwaftr.constants')
local zebra     = require('lib.zebra.constants')
local struct    = require('lib.zebra.message.struct')

local ffi = require('ffi')
local lib = require('core.lib')
local ffi_cast   = ffi.cast
local ffi_new    = ffi.new
local ffi_fill   = ffi.fill
local ffi_typeof = ffi.typeof
local ffi_sizeof = ffi.sizeof
local ffi_metatype = ffi.metatype

local ethertype_ipv4 = constants.ethertype_ipv4
local ethertype_ipv6 = constants.ethertype_ipv6

local struct_cmd_hello_t = struct.cmd_hello_t

local ZebraMessage = {}

function ZebraMessage:_new(opt)
    local opt = opt or {}

    local o = {
        _family   = opt.family or ethertype_ipv4,
        _version  = opt.version or 2,
        _type     = zebra.CMD_HELLO,
        _defaults = {},
        _data     = nil,
        _struct_t = nil,
        _ptr_t    = nil,
    }

    local self = setmetatable(o, { __index = ZebraMessage })
    return self
end

function ZebraMessage:sizeof()
    return ffi_sizeof(self._struct_t)
end

function ZebraMessage:new(opt)
    local zm = self:_new(opt)
    zm._data = ffi_new(zm._struct_t)
    if not zm._data then
        return nil
    end
    -- Set any default values
    for k, v in pairs(zm._defaults) do
        zm:value(k, v)
    end
    return zm
end


function ZebraMessage:new_from_mem(mem, opt)
    local zm = self:_new(opt)
    zm._data = ffi_cast(zm:ptr(), mem)

    if not zm._data then
        return nil
    end
    return zm
end


function ZebraMessage:family()
    return self._family
end


function ZebraMessage:version()
    return self._version
end


function ZebraMessage:type(_type)
    if not _type then
        return self._type
    end

    self._type = _type
    return _type
end


function ZebraMessage:ptr()
    if not self._ptr_t then
        self._ptr_t = ffi_typeof("$*", self._struct_t)
    end
    return self._ptr_t
end


function ZebraMessage:data()
    return self._data
end

function ZebraMessage:_getField(field)
    return self._data[field]
end

function ZebraMessage:_setField(field, value)
    self._data[field] = value
    return self._data[field]
end

function ZebraMessage:value(field, value)
    -- TODO: Find a way to test for existence of field.
    local ok, cur_value = pcall(self._getField, self, field)

    if not ok then
        return
    end

    if value == nil then
        return cur_value
    else
        local ok, new_value = pcall(self._setField, self, field, value)
        if not ok then
            return
        end
        return new_value
    end
end

return { ZebraMessage = ZebraMessage }
