module(..., package.seeall)

local S              = require("syscall")

local app            = require("core.app")
local app_now        = app.now
local util  = require("apps.wall.util")
local const = require("apps.wall.constants")
local lib   = require("core.lib")
local math  = require("math")
local counter        = require("core.counter")
local link           = require("core.link")
local link_nreadable = link.nreadable
local link_receive   = link.receive
local link_transmit  = link.transmit
local link_empty     = link.empty
local os             = require("os")
local os_time        = os.time
local packet         = require("core.packet")
local packet_free    = packet.free
local packet_clone   = packet.clone
local ffi            = require("ffi")
local C              = ffi.C
local ipv4  = require("lib.protocol.ipv4")
local ipv6  = require("lib.protocol.ipv6")
local BasicScanner   = require("apps.ddos.basic_scanner")
local SpaceSaving    = require("apps.ddos.spacesaving")


require("core.link_h")

local function get_time()
    return tonumber(C.get_time_ns())
end

Anomaly = {
    config = {
        core = { required = false },
    },
}

-- I don't know what I'm doing
function Anomaly:new (conf)

    local o = {
        last_report   = 0,
        last_periodic = 0,
        core          = conf.core or 0,
        scanner       = BasicScanner:new(),
        tables        = {},
        aggregations  = {
            { name = 'proto',               fields = { 'proto' }, max_values = 10},
            { name = 'proto_src',           fields = { 'proto', 'src_addr' }, max_values = 2048},
            { name = 'proto_dst',           fields = { 'proto', 'dst_addr' }, max_values = 2048},
            { name = 'proto_src_port',      fields = { 'proto', 'src_port'}, max_values = 2048}, 
            { name = 'proto_dst_port',      fields = { 'proto', 'dst_port'}, max_values = 2048}, 
            { name = 'proto_2way',          fields = { 'proto', 'src_addr', 'dst_addr'}, max_values = 4096}, 
          --  { name = 'proto_2way_src_port', fields = { 'proto', 'src_addr', 'dst_addr', 'src_port'}}, 
          -- { name = 'proto_2way_dst_port', fields = { 'proto', 'src_addr', 'dst_addr', 'dst_port'}}, 
          --  { name = 'proto_5tuple',        fields = { 'proto', 'src_addr', 'dst_addr', 'src_port', 'dst_port'}}, 
        }
    }

    self = setmetatable(o, {__index = Anomaly})

    return self
end



-- Processes a single received packet.
function Anomaly:process_packet(p)
    local tables = self.tables
    local p_info = self.scanner:scan_packet(p)

    if p_info then
        for _, aggregation in ipairs(self.aggregations) do
            local fields = aggregation.fields 
            local name   = aggregation.name
            if not tables[name] then
                tables[name] = SpaceSaving:new(aggregation.max_values or 10, aggregation.half_life or 10)
            end

            -- Generate field values
            local key = {}
            for index, field_name in ipairs(fields) do
                if p_info[field_name] then
                    key[index] = p_info[field_name]
                end
            end
            -- Do not submit if any required field was nil
            if #key == #fields then
                tables[name]:touch(key, get_time())
            end
        end

    end
end


-- Periodic functions here have a resolution of a second or more.
-- Subsecond periodic tasks are not possible
function Anomaly:periodic()
    local now = app_now()

    -- Return if we havent spent at least a second since the last periodic
    if (now - self.last_periodic) < 1 then
        return
    end

    self.last_periodic = now


    -- Only report if >30s has passed
    if (now - self.last_report) > 1 then
        self:report()
        self.last_report = now
    end
end


function Anomaly:report()
    print("\27[2J")
    local tables = self.tables
    for _, aggregation in ipairs(self.aggregations) do
        local name = aggregation.name
        if not tables[name] then
            tables[name] = SpaceSaving:new(aggregation.max_values or 25, aggregation.half_life or 10)
        end
        print(name) 
        for i, v in pairs(tables[name]:getAll(get_time())) do
            if i <= 5  then
                print(string.format("\t%-40s\t\t%10.2f\t%10.2f\t%11d\t%11d", table.concat(v.data, '/'), v.hirate, v.lorate, v.hicount, v.locount))
            end
        end
        print('') 
        print('') 
    end
end


function Anomaly:stop()
end


-- This can be thought of as the application loop
function Anomaly:push()
    local input  = self.input
    local output = self.output.output

    for _, l in ipairs(input) do
        for _ = 1, link_nreadable(l) do
            -- Receive packet
            local p = link_receive(l)
            self:process_packet(p)

            -- Forward packet to any output interfaces
            if output then
                link_transmit(output, packet_clone(p))
            end

            -- Free packet
            packet_free(p)
        end
    end

    -- Run periodic method
    self:periodic()
end
