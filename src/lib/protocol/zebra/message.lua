local header = require('lib.protocol.header')
local zc     = require('lib.zebra.constants')

local ffi = require('ffi')
local lib = require('core.lib')
local ffi_cast   = ffi.cast
local ffi_fill   = ffi.fill
local ffi_typeof = ffi.typeof
local ffi_sizeof = ffi.sizeof

local htons, ntohs = lib.htons, lib.ntohs

local message = subClass(header)

message._name = 'zebra_message'
message._ulp = { method = nil }

message:init({
      [1] = ffi_typeof[[
	    struct {
	       uint8_t    route_type;
	    } __attribute__((packed))
      ]],
   })

function message:new(config)
    local o = message:superClass().new(self)
    o.type = zc.CMD_HELLO
    return o
end

function message:type()

end

return message
