module(..., package.seeall)

local packet   = require("core.packet")
local ffi      = require("ffi")

local receive, transmit = link.receive, link.transmit

local addr_ip = ffi.new("uint8_t[4]")
local addr_ip6 = ffi.new("uint8_t[16]")

local function random_ip(addr)
   for i = 0, ffi.sizeof(addr) - 1 do
      addr[i] = math.random(255)
   end
   return addr
end

local ext_hdr = ffi.new([[
   struct {
      uint8_t next_header;
      uint8_t length;
      uint8_t data[14];
   }  __attribute__((packed))
 ]])
 
 local function push_ext_hdr(dgram, next_header)
    local p = dgram:packet()
    ext_hdr.next_header = next_header
    ext_hdr.length = 1
    local length = ffi.sizeof(ext_hdr)
    p = packet.prepend(p, ext_hdr, length)
    dgram:new(p)
    return length
 end

RandomSource = {
   config = {
      ratio = 0.5 -- 50/50 IPv6 to IPv4
   }
}

function RandomSource:new(conf)
   local o = {
      ratio = conf.ratio,
      eth = require("lib.protocol.ethernet"):new({}),
      ip = require("lib.protocol.ipv4"):new({ protocol = 17 }),
      ip6 = require("lib.protocol.ipv6"):new({ next_header = 17 }),
      udp = require("lib.protocol.udp"):new({}),
      dgram = require("lib.protocol.datagram"):new()
   }
   return setmetatable(o, {__index=RandomSource})
end

function RandomSource:random_packet()
   local p = packet.allocate()
   local payload_size = math.random(9000)
   p.length = payload_size
   self.dgram:new(p)
   self.udp:src_port(math.random(2^16-1))
   self.udp:dst_port(math.random(2^16-1))
   self.dgram:push(self.udp)
   if math.random() > self.ratio then
      self.ip:src(random_ip(addr_ip))
      self.ip:dst(random_ip(addr_ip))
      self.ip:total_length(self.ip:sizeof() + self.udp:sizeof()
                              + payload_size)
      self.ip:ttl(math.random(100))
      self.dgram:push(self.ip)
      self.eth:type(0x0800)
   else
      local next_header = 17
      local ext_hdr_size = 0
      for _ = 1, math.ceil(math.random(3)) do
         ext_hdr_size = ext_hdr_size
            + push_ext_hdr(self.dgram, next_header)
         next_header = 0 -- Hop-by-hop header
      end
      self.ip6:payload_length(ext_hdr_size + self.udp:sizeof()
                                 + payload_size)
      self.ip6:next_header(next_header)
      self.ip6:src(random_ip(addr_ip6))
      self.ip6:dst(random_ip(addr_ip6))
      self.dgram:push(self.ip6)
      self.eth:type(0x86dd)
   end
   self.dgram:push(self.eth)
   return self.dgram:packet()
end

function RandomSource:pull ()
   for _, o in ipairs(self.output) do
      for i = 1, engine.pull_npackets do
         transmit(o, self:random_packet())
      end
   end
end