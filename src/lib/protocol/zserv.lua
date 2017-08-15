local header = require('lib.protocol.header')

local ffi = require('ffi')
local lib = require('core.lib')
local ffi_cast   = ffi.cast
local ffi_fill   = ffi.fill
local ffi_typeof = ffi.typeof
local ffi_sizeof = ffi.sizeof

local htons, ntohs = lib.htons, lib.ntohs

local zserv = subClass(header)

zserv._name = 'zserv'
zserv._ulp = { method = nil }

zserv:init({
      [1] = ffi_typeof[[
	    struct {
	       uint16_t    length;
	       uint8_t     command;
	    } __attribute__((packed))
      ]],
      [2] = ffi_typeof[[
	    struct {
	       uint16_t    length;
	       uint8_t     marker;
	       uint8_t     version;
	       uint16_t    command;
	    } __attribute__((packed))
      ]],
      [3] = ffi_typeof[[
	    struct {
	       uint16_t    length;
	       uint8_t     marker;
	       uint8_t     version;
               uint16_t    vrf_id;
	       uint16_t    command;
	    } __attribute__((packed))
      ]],
   })

-- V2 uses the same header as V1
local types = { v0 = 1, v1 = 2, v2 = 2, v3 = 3 }

function zserv:new(config)
    local o = zserv:superClass().new(self)
    local type = nil

    local version = config.version or 3

    if config.type and types[type] then
        type = config.type
    else
        type = 'v'..version
    end

    local header = o._headers[types[type]]
    o._header = header

    local data = header.data
    header.box[0] = ffi_cast(header.ptr_t, data)

    local data_len = ffi_sizeof(data)

    ffi_fill(data, data_len)

    o:length(config.length or (self:sizeof()+data_len))
    o:marker(config.marker or 255)
    o:version(version)
    o:vrf_id(config.vrf_id or 0)
    o:command(config.command)
    return o
end

function zserv:new_from_mem(mem, size)
   local o      = zserv:superClass().new_from_mem(self, mem, size)
   local header = o._header
   local data   = header.box[0]

   -- Check if this is version 0 or not
   if data.command ~= 255 then
       return o
   end

   -- This is either a version 1 or above header
   header        = o._headers[types['v1']]
   header.box[0] = ffi_cast(header.ptr_t, mem)
   data          = header.box[0]

   if data.version == 1 then
       o._header = header
       return o
   end
   local version_header = types['v'..data.version]

   -- Version header was not 0 or 1 but also unimplemented by this zserv class
   if not version_header then
       o:free()
       return nil
   end

   header        = o._headers[types['v'..version_header]]
   header.box[0] = ffi_cast(header.ptr_t, mem)
   o._header = header
   return o
end

function zserv:length(length)
    local h = self:header()
    if length ~= nil then
        h.length = htons(length)
    end
    return ntohs(h.length)
end

function zserv:marker(marker)
    local h = self:header()
    if marker ~= nil then
        h.marker = marker
    end
    return h.marker
end

function zserv:version(version)
    local h = self:header()
    if version ~= nil then
        h.version = version
    end

    return h.version
end

function zserv:vrf_id(vrf_id)
    local h = self:header()

    if vrf_id ~= nil then
	h.vrf_id = htons(vrf_id)
    end

    if self:version() < 2 then
        return 0
    end

    return ntohs(h.vrf_id)
end

function zserv:command(command)
    local h = self:header()
    if command ~= nil then
        h.command = htons(command)
    end
    return ntohs(h.command)
end

return zserv
