local constants     = require('apps.lwaftr.constants')
local zebra         = require('lib.zebra.constants')
local string        = require('string')
local string_format = string.format
local ffi           = require('ffi')
local lib           = require('core.lib')
local ffi_cast      = ffi.cast
local ffi_new       = ffi.new
local ffi_fill      = ffi.fill
local ffi_typeof    = ffi.typeof
local ffi_sizeof    = ffi.sizeof
local ffi_metatype  = ffi.metatype

local structs = {}

local ethertype_ipv4 = constants.ethertype_ipv4
local ethertype_ipv6 = constants.ethertype_ipv6

structs.cmd_hello = ffi_typeof[[
    struct { uint8_t route_type; } __attribute__((packed))
]]

structs.cmd_router_id_ipv4 = ffi_typeof[[
    struct {
        uint8_t  family;
        uint8_t  prefix[4];
        uint8_t  prefixlen;
    } __attribute__((packed))
]]

structs.cmd_router_id_ipv6 = ffi_typeof[[
    struct {
        uint8_t  family;
        uint8_t  prefix[16];
        uint8_t  prefixlen;
    } __attribute__((packed))
]]

-- We always specify hwaddr as an ethernet mac
structs.cmd_interface_v1 = ffi_typeof(string_format([[
    struct {
        char     name[%d];
        int32_t  index;
        uint8_t  status;
        uint64_t flags;
        uint32_t metric;
        uint32_t mtu_v4;
        uint32_t mtu_v6;
        uint32_t bandwidth;
        uint32_t hwaddr_len;
        uint8_t  hwaddr[6];
    } __attribute__((packed))
]], zebra.INTERFACE_NAMSIZE))

structs.cmd_interface_v3 = ffi_typeof(string_format([[
    struct {
        char     name[%d];
        int32_t  index;
        uint8_t  status;
        uint64_t flags;
        uint32_t metric;
        uint32_t mtu_v4;
        uint32_t mtu_v6;
        uint32_t bandwidth;
        uint32_t llt;
        uint32_t hwaddr_len;
        uint8_t  hwaddr[6];
    } __attribute__((packed))
]], zebra.INTERFACE_NAMSIZE))

structs.cmd_interface_address_ipv4 = ffi_typeof[[
    struct {
        int32_t  index;
        uint8_t  flags;
        uint8_t  family;
        uint8_t  prefix[4];
        uint8_t  prefixlen;
        uint8_t  destination[4];
    } __attribute__((packed))
]]

structs.cmd_interface_address_ipv6 = ffi_typeof[[
    struct {
        int32_t  index;
        uint8_t  flags;
        uint8_t  family;
        uint8_t  prefix[16];
        uint8_t  prefixlen;
        uint8_t  destination[16];
    } __attribute__((packed))
]]

structs.cmd_route_zebra = ffi_typeof[[
    struct {
        uint8_t  type;
        uint8_t  flags;
        uint8_t  message;
        uint16_t safi;
        uint8_t  prefixlen;
        uint8_t  destination[16];
    } __attribute__((packed))
]]

return structs
