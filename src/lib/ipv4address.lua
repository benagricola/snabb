--- IPv4 address handling object.
-- depends on LuaJIT's 64-bit capabilities,
-- both for numbers and bit.* library
local bit = require("bit")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")

local ipv4_addr_t = ffi.typeof('struct { uint32_t addr; }')
local ipv4_addr_mt = {}
local uchar_ptr_t = ffi.typeof('unsigned char *')

ipv4_addr_mt.__index = ipv4_addr_mt

function ipv4_addr_mt:new (addr)
   -- If initialising with c struct, return it
   if ffi.istype(ipv4_addr_t, addr) then
      return addr
   end

   -- Otherwise create new instance of struct
   local ipv4_addr = ipv4_addr_t()

   -- If initialising with uchar_ptr_t, assume IP in raw form in packet
   -- Copy value into struct
   if ffi.istype(uchar_ptr_t, addr) then
      local addr_u32 = ffi.cast("uint32_t", addr)
      ipv4_addr.addr = addr_u32
      return ipv4_addr
   end

   print(addr)
   -- If initialising with string, assume dotted notation IP address
   ipv4_addr.addr = ipv4:pton(addr)
   return ipv4_addr
end

function ipv4_addr_mt:__tostring ()
   local ip = self.addr[0]
   local n1 = bit.band(bit.rshift(ip, 0),  0x000000FF)
   local n2 = bit.band(bit.rshift(ip, 8),  0x000000FF)
   local n3 = bit.band(bit.rshift(ip, 16), 0x000000FF)
   local n4 = bit.band(bit.rshift(ip, 24), 0x000000FF)

   return string.format("%d.%d.%d.%d", n1, n2, n3, n4)
end

function ipv4_addr_mt.__eq (a, b)
   return a.addr == b.addr
end

ipv4_addr_t = ffi.metatype(ipv4_addr_t, ipv4_addr_mt)

return ipv4_addr_mt
