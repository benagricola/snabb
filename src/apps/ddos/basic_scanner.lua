local scanner = require("apps.wall.scanner")
local const   = require("apps.wall.constants")
local lib   = require("core.lib")
local ntohs = lib.ntohs
local ipv4  = require("lib.protocol.ipv4")
local ipv6  = require("lib.protocol.ipv6")

local proto_names = {
    ICMP  = 1,
    IGMP  = 2,
    IPV4  = 4,
    TCP   = 6,
    UDP   = 17,
    GRE   = 47,
    ESP   = 50,
    AH    = 51,
    EIGRP = 88,
    OSPF  = 89,
    ISIS  = 124,
    SCTP  = 132,
}

-- Calculate reverse mapping of above
local proto_nums = {}
for proto_name, proto_num in pairs(proto_names) do
    proto_nums[proto_num] = proto_name
end

-- Extracts src and destination IP / port and layer 3 proto
local BasicScanner = subClass(scanner.Scanner)
BasicScanner._name = "RADISH Basic Packet Scanner"

function BasicScanner:new()
    local s = BasicScanner:superClass().new(self)
    s.proto_nums  = proto_nums    
    s.proto_names = proto_names
    return s
end

function BasicScanner:protocol_name(protocol)
    return self.proto_nums[protocol] or 'Unknown'
end

function BasicScanner:scan_packet(p)
   local key, ip_offset, src_addr, src_port, dst_addr, dst_port = self:extract_packet_info(p)
   if not key then
      return false, nil
   end

   local eth_type = key:eth_type()
   if eth_type == const.ETH_TYPE_IPv4 then
      src_addr = ipv4:ntop(src_addr)
      dst_addr = ipv4:ntop(dst_addr)
   elseif eth_type == const.ETH_TYPE_IPv6 then
      src_addr = ipv6:ntop(src_addr)
      dst_addr = ipv6:ntop(dst_addr)
   end
   if src_port then   
       src_port = ntohs(src_port)
   end
   if dst_port then
       dst_port = ntohs(dst_port)
   end

   return { 
       proto = self:protocol_name(key.ip_proto),
       src_addr = src_addr,
       src_port = src_port,
       dst_addr = dst_addr,
       dst_port = dst_port
   }
end

return BasicScanner
