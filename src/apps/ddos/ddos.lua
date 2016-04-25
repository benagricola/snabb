module(..., package.seeall)

local S             = require("syscall")

local app           = require("core.app")
local app_now       = app.now
local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical
local class_pflua   = require("apps.ddos.classifiers.pflua")
local datagram      = require("lib.protocol.datagram")
local ethernet      = require("lib.protocol.ethernet")
local ipv4          = require("lib.protocol.ipv4")
local ipv6          = require("lib.protocol.ipv6")
local counter       = require("core.counter")
local shm           = require("core.shm")
local ffi           = require("ffi")
local link          = require("core.link")
local link_receive  = link.receive
local link_empty    = link.empty
local link_transmit = link.transmit
local link_receive  = link.receive
local link_nreadable = link.nreadable
local link_nwritable = link.nwritable
local link_receive  = link.receive
local packet        = require("core.packet")
local packet_free   = packet.free
local packet_clone  = packet.clone
local math          = require("math")
local math_max      = math.max
local math_min      = math.min
local math_floor    = math.floor
local math_ceil     = math.ceil
local math_abs      = math.abs
local math_exp      = math.exp
local json          = require("lib.json")
local json_decode   = json.decode
local msgpack       = require("lib.msgpack")
local m_pack        = msgpack.pack
local m_unpack      = msgpack.unpack

local C = ffi.C
local mask = ffi.C.LINK_RING_SIZE-1

require("core.link_h")

Detector = {}

-- I don't know what I'm doing
function Detector:new (_, arg)
    local conf = arg and config.parse_app_arg(arg) or {}

    print(class_pflua)
    local o = {
        config_file_path = conf.config_file_path,
        status_file_path = "/dev/shm/detector-status",
        config_loaded = 0, -- Last time config was loaded
        last_report   = 0,
        last_periodic = 0,
        last_status   = 0,
        core          = conf.core,
        classifier    = class_pflua.new()
    }

    self = setmetatable(o, {__index = Detector})

    log_info("Reading initial config...")

    self:read_config()

    -- datagram object for reuse
    self.d = datagram:new()

    return self
end

function Detector:write_status()
    local status_file = assert(io.open(self.status_file_path, "w"))
    status_file:write(m_pack(self.rules))
    status_file:close()
end

function Detector:read_config()
    local stat = S.stat(self.config_file_path)
    if stat.mtime ~= self.config_loaded then
        log_info("Config file '%s' has been modified, reloading...", self.config_file_path)
        local cfg_file = assert(io.open(self.config_file_path, "r"))
        local cfg_raw  = cfg_file:read("*all")
        cfg_file:close()
        self.config_loaded = stat.mtime
        local cfg_json = json_decode(cfg_raw)
        self:parse_config(cfg_json)
    end
end

function Detector:parse_config(cfg)
    self.classifier:parse_rules(cfg.rules)
end

-- Periodic functions here have a resolution of a second or more.
-- Subsecond periodic tasks are not possible
function Detector:periodic()
    local now = app_now()

    -- Calculate bucket rates and violations
    if now - self.last_periodic > 1 then
        self.classifier:periodic()
        self:read_config()
        self.last_periodic = now
    end

    if now - self.last_status > 1 then
        -- Report to file
        self:write_status()
    end

    if now - self.last_report > 30 then
        self:report()
    end
end

function Detector:push()
    local i = assert(self.input.input, "input port not found")

    while not link_empty(i) do
        self:process_packet(i)
    end
end


function Detector:process_packet(i)
    local p = link_receive(i)
    local classifier = self.classifier
    -- Parse packet
    -- local d = self.d:new(p, ethernet, {delayed_commit = true})

    -- Check packet against BPF rules

    local bucket = classifier:match(p)

    -- If packet didn't match a rule (no bucket returned), ignore
    if bucket == nil then
        -- Free packet
        packet_free(p)
        return
    end

    bucket:add_packet(p.length)

    -- TODO: If rule is in violation, log packet?

    -- Free packet
    packet_free(p)
end



function Detector:print_packet(d)
    -- Top of the stack is 'ethernet'
    -- Next down is AFI, ipv4/ipv6
    local ethernet  = d:parse()
    local ip_hdr    = d:parse()

    local src, dst

    local ethernet_type = ethernet:type()

    local afi

    if ethernet_type == 0x0800 then
        src = ipv4:ntop(ip_hdr:src())
        dst = ipv4:ntop(ip_hdr:dst())
        afi = 'ipv4'
    elseif ethernet_type == 0x86dd then
        src = ipv6:ntop(ip_hdr:src())
        dst = ipv6:ntop(ip_hdr:dst())
        afi = 'ipv6'
    end

    local proto_type = ip_hdr:protocol()

    local proto_hdr = d:parse()

    local src_port = proto_hdr:src_port()
    local dst_port = proto_hdr:dst_port()


    print(table.concat({
        afi,
        " Packet, proto ",
        tostring(proto_type),
        " ",
        src,
        ':',
        src_port,
        ' -> ',
        dst,
        ':',
        dst_port,
        ' matched filter: ',
        rule.filter}
    ))
end


function Detector:get_stats_snapshot()
    return link.stats(self.input.input)
end


function Detector:report()
    if self.last_stats == nil then
        self.last_stats = self:get_stats_snapshot()
        return
    end
    last = self.last_stats
    cur = self:get_stats_snapshot()

    self.last_stats = cur
end


