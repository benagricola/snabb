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
      ratio  = 0.5, -- 50/50 IPv6 to IPv4
      unique = 100,  -- Generate 10 different packets and loop
      size   = 7000,
   }
}

function RandomSource:new(conf)
   local o = {
      ratio = conf.ratio,
      unique = conf.unique,
      size = conf.size,
      p = {},
   }


   local self = setmetatable(o, {__index=RandomSource})
   
   for i = 0, (o.unique - 1) do
      self.p[i] = self:random_packet()
   end
   return self
end

local ipv4 = require("lib.protocol.ipv4")

function RandomSource:random_packet()
   local eth   = require("lib.protocol.ethernet"):new({})
   local ip    = require("lib.protocol.ipv4"):new({ protocol = 17 })
   local ip6   = require("lib.protocol.ipv6"):new({ next_header = 17 })
   local udp   = require("lib.protocol.udp"):new({})
   local dgram = require("lib.protocol.datagram"):new()

   local p = packet.allocate()
   local payload_size = math.random(self.size)

   p.length = payload_size
   dgram:new(p)
   udp:src_port(math.random(2^16-1))
   udp:dst_port(math.random(2^16-1))
   dgram:push(udp)
   if math.random() > self.ratio then
      ip:src(random_ip(addr_ip))
      ip:dst(random_ip(addr_ip))
      ip:total_length(ip:sizeof() + udp:sizeof()
                              + payload_size)
      ip:ttl(math.random(100))
      dgram:push(ip)
      eth:type(0x0800)
   else
      local next_header = 17
      local ext_hdr_size = 0
      for _ = 1, math.ceil(math.random(3)) do
         ext_hdr_size = ext_hdr_size
            + push_ext_hdr(dgram, next_header)
         next_header = 0 -- Hop-by-hop header
      end
      ip6:payload_length(ext_hdr_size + udp:sizeof()
                                 + payload_size)
      ip6:next_header(next_header)
      ip6:src(random_ip(addr_ip6))
      ip6:dst(random_ip(addr_ip6))
      dgram:push(ip6)
      eth:type(0x86dd)
   end
   dgram:push(eth)
   return dgram:packet()
end

function RandomSource:pull ()
   local p
   local unique = self.unique
   for _, o in ipairs(self.output) do
      for i = 1, engine.pull_npackets do
         p = self.p[i%unique]
         transmit(o, packet.clone(p))
      end
   end
end