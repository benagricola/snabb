--- IPv4 address handling object.
local bit        = require("bit")
local bit_band   = bit.band
local bit_rshift = bit.rshift
local bit_lshift = bit.lshift
local bit_tobit  = bit.tobit
local bit_bxor   = bit.bxor

local string = require("string")
local string_format = string.format

local ffi = require("ffi")
local ffi_new = ffi.new
local ffi_istype = ffi.istype
local ffi_cast = ffi.cast
local ffi_string = ffi.string

local C = ffi.C

local ipv4 = require("lib.protocol.ipv4")

local ipv4_addr_t = ffi.typeof('struct { uint32_t addr; }')
local ipv4_addr_mt = {}
local uchar_ptr_t = ffi.typeof('unsigned char *')

-- Pre-calculate masks
local bin_masks = {}
for i=1,32 do
    bin_masks[i] = bit_lshift(bit_tobit((2^i)-1), 32-i)
end

local bin_inverted_masks = {}
for i=1,32 do
    bin_inverted_masks[i] = bit_bxor(bin_masks[i], bin_masks[32])
end

ipv4_addr_mt.__index = ipv4_addr_mt

function ipv4_addr_mt:new (addr)
   -- If initialising with struct, return
   if ffi_istype(ipv4_addr_t, addr) then
      return addr
   end

   -- Otherwise create new instance
   local ipv4_addr = ipv4_addr_t()

   -- If initialising with uchar_ptr_t, assume IP in raw form in packet
   if ffi_istype(uchar_ptr_t, addr) then
      ipv4_addr.addr = ffi_cast("uint32_t", addr)

   -- If initialising with string, assume dotted notation IP address
   else
      ipv4_addr.addr = ipv4:pton(addr)
   end

   return ipv4_addr
end


function ipv4_addr_mt:mask(mask)
    if mask < 1 or mask > 32 then
        return false
    end

    self.addr = bit_band(bin_inverted_masks[mask], self.addr)
    return true
end


function ipv4_addr_mt:__tostring ()
   local ip = self.addr
   local n1 = bit_band(bit_rshift(ip, 0),  0x000000FF)
   local n2 = bit_band(bit_rshift(ip, 8),  0x000000FF)
   local n3 = bit_band(bit_rshift(ip, 16), 0x000000FF)
   local n4 = bit_band(bit_rshift(ip, 24), 0x000000FF)

   return string_format("%d.%d.%d.%d", n1, n2, n3, n4)
end

function ipv4_addr_mt.__eq (a, b)
   return a.addr == b.addr
end

function ipv4_addr_mt:top()
   local p = ffi_new("char[?]", 16)
   local c_str = C.inet_ntop(2, self.addr, p, 16)
   return ffi_string(c_str)
end

function ipv4_addr_mt:ton()
    return self.addr
end

ipv4_addr_t = ffi.metatype(ipv4_addr_t, ipv4_addr_mt)

return ipv4_addr_mt
