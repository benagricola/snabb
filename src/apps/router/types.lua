module(...,package.seeall)

local app       = require("core.app")
local bit       = require("bit")
local ctable    = require("lib.ctable")
local constants = require("apps.lwaftr.constants")
local counter   = require("core.counter")
local ffi       = require("ffi")
local lib       = require("core.lib")
local link      = require("core.link")
local math      = require("math")
local packet    = require("core.packet")
local pmu       = require("lib.pmu")

local bit_rshift   = bit.rshift
local counter_add  = counter.add
local ffi_cast     = ffi.cast
local ffi_typeof   = ffi.typeof
local ffi_sizeof   = ffi.sizeof
local ffi_metatype = ffi.metatype
local ffi_new      = ffi.new
local ffi_copy     = ffi.copy
local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl
local math_min     = math.min
local now          = app.now

local p_free, p_clone = packet.free, packet.clone
local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

-- Constants
local ether_type_arp     = 0x0806
local ether_type_ipv4    = 0x0800
local ether_type_ipv6    = 0x86dd
local arp_oper_request   = 1
local arp_oper_reply     = 2
local arp_htype_ethernet = 1
local arp_ptype_ipv4     = 0x0800
local arp_hlen_ethernet  = 6
local arp_plen_ipv4      = 4
local ip_proto_icmp      = 1

local mac_addr_t           = ffi_typeof("uint8_t[6]")
local ethernet_header_type = ffi_metatype(ffi_typeof([[
   struct {
      uint8_t  ether_dhost[6];
      uint8_t  ether_shost[6];
      uint16_t ether_type;
   }  __attribute__((packed))
]]), {
    __index = {
        dst = function(self, var)
            if var ~= nil then
                ffi_copy(self.ether_dhost, var, 6)
            end

            return self.ether_dhost
        end,
        src = function(self, var)
            if var ~= nil then
                ffi_copy(self.ether_shost, var, 6)
            end

            return self.ether_shost
        end,
        type = function(self, var)
            if var ~= nil then
                self.ether_type = htons(self.ether_type)
            end
            return ntohs(self.ether_type)
        end,
        swap = function(self)
	   local tmp = mac_addr_t()
	   ffi_copy(tmp, self.ether_dhost, 6)
	   ffi_copy(self.ether_dhost, self.ether_shost, 6)
	   ffi_copy(self.ether_shost, tmp, 6)
        end,
    }
})

ethernet_header_ptr_type = ffi_typeof("$*", ethernet_header_type)
ethernet_header_size = ffi_sizeof(ethernet_header_type)
