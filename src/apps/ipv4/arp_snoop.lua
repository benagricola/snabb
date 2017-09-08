-- ARP snooping application.
-- Snoops on arp replies from southbound links, forwards other traffic
-- Rewrites traffic from northbound links based on stored mac, otherwise drops it

-- Is able to send ARP requests but does *not* respond to ARP requests
-- Assumes something else northbound (linux kernel?) will handle replies.

module(..., package.seeall)

local bit      = require("bit")
local ffi      = require("ffi")
local math     = require("math")
local now      = require("core.app").now
local cltable  = require("lib.cltable")
local packet   = require("core.packet")
local link     = require("core.link")
local lib      = require("core.lib")
local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ipv4     = require("lib.protocol.ipv4")

local C = ffi.C
local receive, transmit = link.receive, link.transmit
local htons, ntohs = lib.htons, lib.ntohs
local math_min = math.min
local packet_free, packet_clone = packet.free, packet.clone
local l_transmit, l_receive, l_nreadable, l_nwritable = link.transmit, link.receive, link.nreadable, link.nwritable

local ether_header_t = ffi.typeof [[
/* All values in network byte order.  */
struct {
   uint8_t  dhost[6];
   uint8_t  shost[6];
   uint16_t type;
} __attribute__((packed))
]]
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
local ether_arp_header_t = ffi.typeof(
   'struct { $ ether; $ arp; } __attribute__((packed))',
   ether_header_t, arp_header_t)
local ether_header_ptr_t = ffi.typeof('$*', ether_header_t)
local ether_header_len = ffi.sizeof(ether_header_t)
local ether_arp_header_ptr_t = ffi.typeof('$*', ether_arp_header_t)
local ether_arp_header_len = ffi.sizeof(ether_arp_header_t)
local ether_type_arp = 0x0806
local ether_type_ipv4 = 0x0800
local arp_oper_request = 1
local arp_oper_reply = 2
local arp_htype_ethernet = 1
local arp_ptype_ipv4 = 0x0800
local arp_hlen_ethernet = 6
local arp_plen_ipv4 = 4

local mac_unknown = ethernet:pton("00:00:00:00:00:00")
local mac_broadcast = ethernet:pton("ff:ff:ff:ff:ff:ff")

local function make_arp_request_tpl(src_mac, src_ipv4)
   local pkt = packet.allocate()
   pkt.length = ether_arp_header_len

   local h = ffi.cast(ether_arp_header_ptr_t, pkt.data)
   h.ether.dhost = mac_broadcast
   h.ether.shost = src_mac
   h.ether.type = htons(ether_type_arp)
   h.arp.htype, h.arp.ptype = htons(arp_htype_ethernet), htons(arp_ptype_ipv4)
   h.arp.hlen, h.arp.plen = arp_hlen_ethernet, arp_plen_ipv4
   h.arp.oper = htons(arp_oper_request)
   h.arp.sha = src_mac
   h.arp.spa = src_ipv4
   h.arp.tha = mac_unknown
   return h, pkt
end

local function is_arp(p)
   if p.length < ether_arp_header_len then return false end
   local h = ffi.cast(ether_arp_header_ptr_t, p.data)
   return ntohs(h.ether.type) == ether_type_arp
end

local function copy_len(src, len)
   local dst = ffi.new('uint8_t['..len..']')
   ffi.copy(dst, src, len)
   return dst
end

ARPSnoop = {}

local arp_config_params = {
   -- Physical interface details required
   self_mac = { required=true },
   self_ip  = { required=true },
}

function ARPSnoop:new(conf)
   local o = lib.parse(conf, arp_config_params)

   self.mac_table = cltable.new({
       key_type           = ffi.typeof('uint8_t[4]'), -- IPv4 Address
       -- Value is { mac = ffi.typeof('uint8_t[6]'), time }
       max_occupancy_rate = 0.4,
       initial_size       = 100,
   })

   self.arp_request_interval = 10 -- Request arp updates every 10s
   self.arp_expired_interval = 60 -- Remove records with no reply in 60s
   self.arp_next_request     = now()

   local arp_header, arp_packet = make_arp_request_tpl(o.self_mac, o.self_ip)
   self.arp_header = arp_header
   self.arp_packet = arp_packet
   return setmetatable(o, {__index=ARPSnoop})
end

function ARPSnoop:maybe_send_arp_request(output)
   local cur_now = now()

   if self.arp_next_request > cur_now then return end

   local arp_expired_interval = self.arp_expired_interval
   local arp_request_interval = self.arp_request_interval

   for ip, mac in cltable.pairs(self.mac_table) do
      local last_update = mac.time

      if (cur_now - arp_expired_interval) > last_update then
          print(("ARPSnoop: Expiring '%s'"):format(ipv4:ntop(ip)))
          self.mac_table[ip] = nil

      elseif (cur_now - self.arp_request_interval) > last_update then
          print(("ARPSnoop: Resolving '%s'"):format(ipv4:ntop(ip)))
          self:send_arp_request(output, ip)
      end
   end

   self.arp_next_request = cur_now + self.arp_request_interval / 3
end


function ARPSnoop:send_arp_request(output, ip)
   local h = self.arp_header
   local p = self.arp_packet

   -- Set IP we're asking for
   h.arp.tpa = ip
   transmit(output, packet_clone(p))
end

function ARPSnoop:save_mac(ip, mac)
    local mac_table = self.mac_table
    mac_table[ip] = { mac = mac, time = now() }
end

function ARPSnoop:resolve_mac(ip)
    local mac_table = self.mac_table
    local mac = mac_table[ip]
    local output = self.output.south

    -- If mac entry exists and has a stored mac, return
    if mac and mac.mac then return mac.mac end

    -- If this is the first time we've seen this IP recently
    if not mac then
        print(("ARPSnoop: Resolving '%s'"):format(ipv4:ntop(ip)))
        self:send_arp_request(output, ip)
        -- Save with invalid mac which will be updated on reply
        self:save_mac(ip, nil)
        return
    end

    -- Otherwise we have no valid mac but we've already sent
    -- a request - do nothing, the interval refresher will
    -- pick this up if it becomes available (we dont want to send
    -- an ARP request for each packet which has an unresolvable mac)
    return
end

function ARPSnoop:is_arp_reply(h)
    if ntohs(h.arp.htype) ~= arp_htype_ethernet or
     ntohs(h.arp.ptype) ~= arp_ptype_ipv4 or
     h.arp.hlen ~= 6 or h.arp.plen ~= 4 then
        return false
    end

    return ntohs(h.arp.oper) == arp_oper_reply
end

function ARPSnoop:snoop_south(input, output)
    local mac_table = self.mac_table
    local p_count = math_min(l_nreadable(input), l_nwritable(output))
    for _ = 1, p_count do
        local p = l_receive(input)

        if p.length < ether_header_len then
            -- Packet too short.
            packet_free(p)
        elseif is_arp(p) then
            local h = ffi.cast(ether_arp_header_ptr_t, p.data)

            -- Snoop arp reply packet
            if self:is_arp_reply(h) then
                local ip  = copy_len(h.arp.spa, 4)
                local mac = copy_len(h.arp.sha, 6)
                print(("ARPSnoop: Resolved '%s' to %s"):format(ipv4:ntop(ip), ethernet:ntop(mac)))
                self:save_mac(ip, mac)
            end
        end

        l_transmit(output, p)
    end
end

function ARPSnoop:forward_north(input, output)
    local p_count = math_min(l_nreadable(input), l_nwritable(output))
    for _ = 1, p_count do
        local p = l_receive(input)

        if p.length < ether_header_len then
            -- Packet too short.
            packet_free(p)
        end

        l_transmit(output, p)
    end
end

function ARPSnoop:push()
   local isouth, osouth = self.input.south, self.output.south

   -- Northbound -> Southbound traffic bypasses this app
   local onorth = self.output.north

   self:snoop_south(isouth, onorth)

   -- Assume all north->south traffic has modified MAC from router
   --self:forward_north(inorth, osouth)

   -- Send ARP requests for known addresses which are > self.arp_request_interval
   self:maybe_send_arp_request(osouth)
end
