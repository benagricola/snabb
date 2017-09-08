local constants = require('apps.lwaftr.constants')
local zebra     = require('lib.zebra.constants')
local struct    = require('lib.zebra.message.struct')
local base      = require('lib.zebra.message.base')

local ethertype_ipv4 = constants.ethertype_ipv4
local ethertype_ipv6 = constants.ethertype_ipv6

local struct_cmd_hello                  = struct.cmd_hello
local struct_cmd_router_id_ipv4         = struct.cmd_router_id_ipv4
local struct_cmd_router_id_ipv6         = struct.cmd_router_id_ipv6
local struct_cmd_interface_v1           = struct.cmd_interface_v1
local struct_cmd_interface_v3           = struct.cmd_interface_v3
local struct_cmd_interface_address_ipv4 = struct.cmd_interface_address_ipv4
local struct_cmd_interface_address_ipv6 = struct.cmd_interface_address_ipv6

local message = {}

-- CMD_HELLO
message.ZebraHello = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraHello:_new(opt)
    local o     = base.ZebraMessage:_new(opt)
    o._struct_t = struct_cmd_hello
    return setmetatable(self, { __index = o })
end

-- CMD_ROUTER_ID_{ADD,DELETE,UPDATE}
message.ZebraRouterID = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraRouterID:_new(opt)
    local o     = base.ZebraMessage:_new(opt)
    if opt.family == ethertype_ipv4 then
        o._struct_t = struct_cmd_router_id_ipv4
    else
        o._struct_t = struct_cmd_router_id_ipv6
    end

    return setmetatable(self, { __index = o })
end

-- CMD_INTERFACE_{ADD,DELETE,UPDATE}
message.ZebraInterface = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraInterface:_new(opt)
    local o = base.ZebraMessage:_new(opt)
    o._defaults = {
        hwaddr_len = 6,
    }
    if opt.version < 3 then
        o._struct_t = struct_cmd_interface_v1
    else
        o._struct_t = struct_cmd_interface_v3
    end

    return setmetatable(self, { __index = o })
end

-- CMD_INTERFACE_ADDRESS_{ADD,DELETE,UPDATE}
message.ZebraInterfaceAddress = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraInterfaceAddress:_new(opt)
    local o     = base.ZebraMessage:_new(opt)
    if opt.family == ethertype_ipv4 then
        o._struct_t = struct_cmd_interface_address_ipv4
    else
        o._struct_t = struct_cmd_interface_address_ipv6
    end

    return setmetatable(self, { __index = o })
end

message.ZebraRedistribute = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraRedistribute:_new(opt)
    local o     = base.ZebraMessage:_new(opt)
    o._struct_t = struct_cmd_hello
    return setmetatable(self, { __index = o })
end

-- CMD_ROUTE_{ADD,DELETE,UPDATE}
message.ZebraRoute = setmetatable({}, { __index = base.ZebraMessage })
function message.ZebraRoute:_new(opt)
    local o     = base.ZebraMessage:_new(opt)
    if opt.origin == 'zebra' then
        o._struct_t = struct_cmd_route_zebra
    else
        o._struct_t = struct_cmd_route_proto
    end

    return setmetatable(self, { __index = o })
end

return message
