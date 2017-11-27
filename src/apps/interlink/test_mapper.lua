-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

local worker = require("core.worker")
local interlink = require("lib.interlink")
local Mapper = require("apps.interlink.mapper")
local Sink = require("apps.basic.basic_apps").Sink

worker.start("source",
             [[require("apps.interlink.test_source_mapper").start()]])

local c = config.new()

config.app(c, "mapper", Mapper, {})
config.app(c, "sink1", Sink)
config.app(c, "sink2", Sink)
config.link(c, "mapper.testname1->sink1.input")
config.link(c, "mapper.testname2->sink2.input")

engine.configure(c)
engine.main({duration=10, report={showlinks=true}})

for w, s in pairs(worker.status()) do
   print(("worker %s: pid=%s alive=%s status=%s"):format(
         w, s.pid, s.alive, s.status))
end
local stats = link.stats(engine.app_table["sink1"].input.input)
print(stats.txpackets / 1e6 / 10 .. " Mpps")
local stats = link.stats(engine.app_table["sink2"].input.input)
print(stats.txpackets / 1e6 / 10 .. " Mpps")
