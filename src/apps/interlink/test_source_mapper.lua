-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

local Mapper = require("apps.interlink.mapper")
local Source = require("apps.basic.basic_apps").Source

local m = {}
function m.start ()
   local c = config.new()
   config.app(c, "mapper", Mapper, {})
   config.app(c, "source1", Source)
   config.app(c, "source2", Source)
   config.link(c, "source1.output->mapper.testname1")
   config.link(c, "source2.output->mapper.testname2")
   engine.configure(c)
   engine.main()
end

return m.start()
