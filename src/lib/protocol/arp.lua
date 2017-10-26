-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local lib = require("core.lib")
local header   = require("lib.protocol.header")
local ethernet = require("lib.protocol.ethernet")
local htons, ntohs, htonl, ntohl =
   lib.htons, lib.ntohs, lib.htonl, lib.ntohl

local arp_header_t = ffi.typeof [[
/* All values in network byte order.  */
struct {
   uint16_t htype;      /* Hardware type */
   uint16_t ptype;      /* Protocol type */
   uint8_t  hlen;       /* Hardware address length */
   uint8_t  plen;       /* Protocol address length */
   uint16_t oper;       /* Operation */
   uint8_t  sha[6];     /* Sender hardware address */
   uint8_t  spa[4];     /* Sender protocol address */
   uint8_t  tha[6];     /* Target hardware address */
   uint8_t  tpa[4];     /* Target protocol address */
} __attribute__((packed))
]]

local arp_header_t_size = ffi.sizeof(arp_header_t)

local arp_oper_request   = 1
local arp_oper_reply     = 2
local arp_htype_ethernet = 1
local arp_ptype_ipv4     = 0x0800
local arp_hlen_ethernet  = 6
local arp_plen_ipv4      = 4
local mac_unknown        = ethernet:pton("00:00:00:00:00:00")
local mac_broadcast      = ethernet:pton("ff:ff:ff:ff:ff:ff")

local arp = subClass(header)

-- Class variables
arp._name = "arp"
arp._ulp = {
   class_map = {},
   method    = nil }
arp:init(
   {
      [1] = arp_header_t,
   })

-- Class methods

function arp:new (config)
   local o = arp:superClass().new(self)
   -- Set hlen and plen based on htype and ptype automatically
   o:htype(config.htype or arp_htype_ethernet) -- htype default to ethernet
   o:ptype(config.ptype or arp_ptype_ipv4)     -- ptype default to ipv4

   o:oper(config.oper or arp_oper_request)
   o:sha(config.sha or mac_unknown)
   o:tha(config.tha or mac_unknown)
   o:spa(config.spa)
   o:tpa(config.tpa)
   return o
end

-- Instance methods
function arp:htype(htype)
   if htype ~= nil then
      if htype == arp_htype_ethernet then
          self:hlen(arp_hlen_ethernet)
      end
      self:header().htype = htons(htype)
   else
      return ntohs(self:header().htype)
   end
end

function arp:hlen(hlen)
   if hlen ~= nil then
      self:header().hlen  = hlen
   else
      return self:header().hlen
   end
end

function arp:ptype(ptype)
   if ptype ~= nil then
      if ptype == arp_ptype_ipv4 then
          self:plen(arp_plen_ipv4)
      end
      self:header().ptype = htons(ptype)
   else
      return ntohs(self:header().ptype)
   end
end

function arp:plen(plen)
   if plen ~= nil then
      self:header().plen  = plen
   else
      return self:header().plen
   end
end

function arp:oper(oper)
   if oper ~= nil then
      self:header().oper = htons(oper)
   else
      return ntohs(self:header().oper)
   end
end

function arp:sha(sha)
   if sha ~= nil then
      ffi.copy(self:header().sha, sha, self:header().hlen)
   else
      return self:header().sha
   end
end

function arp:tha(tha)
   if tha ~= nil then
      ffi.copy(self:header().tha, tha, self:header().hlen)
   else
      return self:header().tha
   end
end

function arp:spa(spa)
   if spa ~= nil then
      ffi.copy(self:header().spa, spa, self:header().plen)
   else
      return self:header().spa
   end
end

function arp:tpa(tpa)
   if tpa ~= nil then
      ffi.copy(self:header().tpa, tpa, self:header().plen)
   else
      return self:header().tpa
   end
end


function selftest()
   local arp_address = "192.168.1.1"
   assert(arp_address == arp:ntop(arp:pton(arp_address)),
      'arp text to binary conversion failed.')

   test_arp_checksum()

   local arphdr = arp:new({})
   assert(C.ntohs(arphdr:header().ihl_v_tos) == 0x4500,
      'arp header field ihl_v_tos not initialized correctly.')
end

arp.selftest = selftest

return arp
