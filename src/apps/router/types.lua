module(...,package.seeall)

local app       = require("core.app")
local bit       = require("bit")
local ctable    = require("lib.ctable")
local constants = require("apps.lwaftr.constants")
local counter   = require("core.counter")
local ffi       = require("ffi")
local ipsum     = require("lib.checksum").ipsum
local lib       = require("core.lib")
local link      = require("core.link")
local math      = require("math")
local packet    = require("core.packet")
local pmu       = require("lib.pmu")

local bitfield     = lib.bitfield
local bit_rshift   = bit.rshift
local C            = ffi.C
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
local l_transmit, l_receive, l_nreadable, l_nwriteable = link.transmit, link.receive, link.nreadable, link.nwriteable

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
local ipv4_addr_t          = ffi_typeof("uint8_t[4]")
local uint8_t_ptr          = ffi_typeof("uint8_t *")
local ipv4_addr_t_size     = ffi_sizeof(ipv4_addr_t)

local ipv4_pseudo_header_type = ffi_typeof([[
      struct {
      uint8_t  src_ip[4];
      uint8_t  dst_ip[4];
      uint8_t  ulp_zero;
      uint8_t  ulp_protocol;
      uint16_t ulp_length;
      } __attribute__((packed))
]])

local ethernet_header_type = ffi_metatype(ffi_typeof([[
   struct {
      uint8_t  f_ether_dhost[6];
      uint8_t  f_ether_shost[6];
      uint16_t f_ether_type;
   }  __attribute__((packed))
]]), {
    __index = {
	sizeof = function(self)
	   return ffi_sizeof(self)
	end,
        dst = function(self, var)
            if var ~= nil then
                ffi_copy(self.f_ether_dhost, var, 6)
                return
            end
            return self.f_ether_dhost
        end,
        src = function(self, var)
            if var ~= nil then
                self.f_ether_shost = var
                ffi_copy(self.f_ether_shost, var, 6)
                return
            end
            return self.f_ether_shost
        end,
        type = function(self, var)
            if var ~= nil then
                self.f_ether_type = htons(self.f_ether_type)
                return
            end
            return ntohs(self.f_ether_type)
        end,
        swap = function(self)
	   local tmp = mac_addr_t()
	   ffi_copy(tmp, self.f_ether_dhost, 6)
	   ffi_copy(self.f_ether_dhost, self.f_ether_shost, 6)
	   ffi_copy(self.f_ether_shost, tmp, 6)
        end,
    }
})

ethernet_header_ptr_type = ffi_typeof("$*", ethernet_header_type)
ethernet_header_size     = ffi_sizeof(ethernet_header_type)

local arp_header_type = ffi_metatype(ffi_typeof([[
    /* All values in network byte order.  */
    struct {
       uint16_t f_htype;      /* Hardware type */
       uint16_t f_ptype;      /* Protocol type */
       uint8_t  f_hlen;       /* Hardware address length */
       uint8_t  f_plen;       /* Protocol address length */
       uint16_t f_oper;       /* Operation */
       uint8_t  f_sha[6];     /* Sender hardware address */
       uint8_t  f_spa[4];     /* Sender protocol address */
       uint8_t  f_tha[6];     /* Target hardware address */
       uint8_t  f_tpa[4];     /* Target protocol address */
    } __attribute__((packed))
]]), {
    __index = {
	sizeof = function(self)
	   return 28
	end,
        htype = function(self, var)
            if var ~= nil then
                self.f_htype = htons(var)
                if var == arp_htype_ethernet then
                   self:hlen(arp_hlen_ethernet)
                end
                return
            end
            return ntohs(self.f_htype)
        end,
        ptype = function(self, var)
            if var ~= nil then
                self.f_ptype = htons(var)
                if var == arp_ptype_ipv4 then
                   self:plen(arp_plen_ipv4)
                end
                return
            end
            return ntohs(self.f_ptype)
        end,
        hlen = function(self, var)
            if var ~= nil then
                self.f_hlen = var
                return
            end
            return self.f_hlen
        end,
        plen = function(self, var)
            if var ~= nil then
                self.f_plen = var
                return
            end
            return self.f_plen
        end,
        oper = function(self, var)
            if var ~= nil then
                self.f_oper = htons(var)
                return
            end
            return ntohs(self.f_oper)
        end,
        sha = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_sha, var, self.f_hlen)
                return
	    end
	    return self.f_sha
        end,
        tha = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_tha, var, self.f_hlen)
                return
	    end
	    return self.f_tha
        end,
        spa = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_spa, var, self.f_plen)
                return
	    end
	    return self.f_spa
        end,
        tpa = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_tpa, var, self.f_plen)
                return
	    end
	    return self.f_tpa
        end,
    }
})

arp_header_ptr_type = ffi_typeof("$*", arp_header_type)
arp_header_size     = ffi_sizeof(arp_header_type)


local ipv4_header_type = ffi_metatype(ffi_typeof([[
    struct {
       uint16_t f_ihl_v_tos; // ihl:4, version:4, tos(dscp:6 + ecn:2)
       uint16_t f_total_length;
       uint16_t f_id;
       uint16_t f_frag_off; // flags:3, fragmen_offset:13
       uint8_t  f_ttl;
       uint8_t  f_protocol;
       uint16_t f_checksum;
       uint8_t  f_src_ip[4];
       uint8_t  f_dst_ip[4];
    } __attribute__((packed))
]]), {
    __index = {
	sizeof = function(self)
	   return 20
	end,
        version = function(self, var)
            return bitfield(16, self, 'f_ihl_v_tos', 0, 4, var)
        end,
        ihl = function(self, var)
            return bitfield(16, self, 'f_ihl_v_tos', 4, 4, var)
        end,
        dscp = function(self, var)
            return bitfield(16, self, 'f_ihl_v_tos', 8, 6, var)
        end,
        ecn = function(self, var)
            return bitfield(16, self, 'f_ihl_v_tos', 14, 2, var)
        end,
        total_length = function(self, var)
            if var ~= nil then
                self.f_total_length = htons(var)
                return
            end
            return ntohs(self.f_total_length)
        end,
        id = function(self, var)
            if var ~= nil then
                self.f_id = htons(var)
                return
            end
            return ntohs(self.f_id)
        end,
        flags = function(self, var)
            return bitfield(16, self, 'f_frag_off', 0, 3, var)
        end,
        frag_off = function(self, var)
            return bitfield(16, self, 'f_frag_off', 3, 13, var)
        end,
        ttl_decr = function(self)
            self.f_ttl = self.f_ttl - 1
	    -- Incrementally update checksum
	    -- Subtracting 1 from the TTL involves *adding* 1 or 256 to the checksum - thanks ones complement
	    -- TODO: May need further rshift? Seems to work for the moment??
            local sum = ntohs(self.f_checksum) + 0x100
            self.f_checksum = htons(sum + bit_rshift(sum, 16))
            return self.f_ttl
        end,
        ttl = function(self, var)
            if var ~= nil then
                self.f_ttl = var
                return
            end
            return self.f_ttl
        end,
        protocol = function(self, var)
            if var ~= nil then
                self.f_protocol = var
                return
            end
            return self.f_protocol
        end,
        checksum = function(self)
	    self.f_checksum = 0
	    self.f_checksum = htons(ipsum(ffi_cast(uint8_t_ptr, self),
						20, 0))
            return ntohs(self.f_checksum)
        end,
        src = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_src_ip, var, ipv4_addr_t_size)
                return
	    end
	    return self.f_src_ip
        end,
        dst = function(self, var)
	    if var ~= nil then
	        ffi_copy(self.f_dst_ip, var, ipv4_addr_t_size)
                return
	    end
	    return self.f_dst_ip
        end,
	src_eq = function(self, ip)
	   return C.memcmp(ip, self.f_src_ip, ipv4_addr_t_size) == 0
	end,
	dst_eq = function(self, ip)
	   return C.memcmp(ip, self.f_dst_ip, ipv4_addr_t_size) == 0
	end,
	pseudo_header = function (self, ulplen, proto)
	   local ph = ipv4_pseudo_header_type()
	   ffi_copy(ph, self.src_ip, 2*ipv4_addr_t_size)  -- Copy source and destination
	   ph.ulp_length = htons(ulplen)
	   ph.ulp_protocol = proto
	   return ph
	end
    }
})

ipv4_header_ptr_type = ffi_typeof("$*", ipv4_header_type)
ipv4_header_size     = ffi_sizeof(ipv4_header_type)

mac_v4_entry_t = ffi_typeof([[
   struct {
      uint8_t  ip[4];
      uint32_t expires;
      uint8_t  mac[6];
   }
]])

fib_v4_entry_t = ffi_typeof([[
   struct {
      uint32_t expires;
      uint32_t int_idx;
      uint8_t  next_ip[4];
      uint8_t  direct;
      uint8_t  src_mac[6];
      uint8_t  dst_mac[6];
      uint32_t refcount;
   }
]])

rtupdate_hdr_t = ffi_typeof([[
   struct {
      uint32_t prefix;
      uint8_t  mask;
   }

]])
