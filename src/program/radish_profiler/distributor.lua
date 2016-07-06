local link_start = tonumber(main.parameters[1]) or 1
local link_end   = tonumber(main.parameters[2]) or 1 
local core       = tonumber(main.parameters[3]) or 1 -- Default first core

local S          = require("syscall")
-- Bind to a core
S.sched_setaffinity(nil, {core})

local pcap       = require("apps.pcap.pcap")
local basic_apps = require("apps.basic.basic_apps")
local transmit   = require("apps.inter_proc.transmit")
local ddos       = require("apps.dosprotect.dosprotect")


local c = config.new()


--config.app(c, "capture", pcap.PcapReader, "/root/dos-attack.pcap")
config.app(c, "capture", ddos.Flooder,256)
config.app(c, "splitrr", ddos.SplitRR)
--config.app(c, "loop", basic_apps.Repeater)

--config.link(c, "capture.output -> loop.input")
config.link(c, "capture.output -> splitrr.input")

-- Multiple 'Receive' apps read packet and send to a dosprotect rule filter app
for i = link_start, link_end do
    print("Transmitting to link ddostop_" .. i)
    config.app(c,  "transmit_" .. i, transmit, {linkname='ddostop_' .. i})
    config.link(c, "splitrr.output_"..i.." -> transmit_"..i..".input")
end

--engine.busywait = true
engine.configure(c)
engine.main({duration=30,report = {showlinks=true, showapps=true}})
