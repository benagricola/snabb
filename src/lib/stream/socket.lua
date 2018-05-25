-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- A stream IO implementation for sockets.

module(..., package.seeall)

local bit  = require('bit')
local file = require('lib.stream.file')
local S    = require('syscall')

local Socket = {}
local Socket_mt = {__index = Socket}

local sigpipe_handler

function socket(domain, stype, protocol)
   if sigpipe_handler == nil then sigpipe_handler = S.signal('pipe', 'ign') end
   local fd = assert(S.socket(domain, stype, protocol))
   file.init_nonblocking(fd)
   return setmetatable({fd=fd}, Socket_mt)
end

function Socket:listen_unix(file)
   local sa = S.t.sockaddr_un(file)
   self.scratch_sockaddr = S.t.sockaddr_un()
   assert(self.fd:bind(sa))
   assert(self.fd:listen())
end

function Socket:listen_netlink(groups)
   local sa = S.t.sockaddr_nl()

   -- Convert groups into bit shifted value
   for _, group in ipairs(groups) do
      local gv = assert(S.c.RTNLGRP[group])
      sa.groups = bit.bor(sa.groups, (bit.lshift(1, gv - 1)))
   end

   assert(self.fd:bind(sa))
   return self
end

-- TODO: Must be a nicer way to avoid implementing this?
function Socket:getsockname()
   return self.fd:getsockname()
end

function Socket:seq()
   return self.fd:seq()
end

function Socket:recvmsg(m)
   while true do
      local len, err = self.fd:recvmsg(m)
      if len then
         return len, nil
      elseif err.AGAIN or err.WOULDBLOCK then
         file.wait_for_readable(self.fd)
      else
         error(tostring(err))
      end
   end
end

function Socket:sendmsg(m)
   while true do
      local len, err = self.fd:sendmsg(m)
      if len then
         return len, nil
      elseif err.AGAIN or err.WOULDBLOCK then
         file.wait_for_writable(self.fd)
      else
         error(tostring(err))
      end
   end
end

function Socket:accept()
   while true do
      local fd, err = self.fd:accept(self.scratch_sockaddr)
      if fd then
         return file.fdopen(fd)
      elseif err.AGAIN or err.WOULDBLOCK then
         file.wait_for_readable(self.fd)
      else
         error(tostring(err))
      end
   end
end

function Socket:connect(sa)
   local ok, err = self.fd:connect(sa)
   if not ok and err.INPROGRESS then
      -- Bonkers semantics; see connect(2).
      file.wait_for_writable(self.fd)
      local err = assert(s:getsockopt("socket", "error"))
      if err == 0 then ok = true
      else err = S.t.error(err) end
   end
   if ok then
      local fd = self.fd
      self.fd = nil
      return file.fdopen(fd)
   end
   error(tostring(err))
end

function Socket:connect_unix(file, stype)
   local sa = S.t.sockaddr_un(file)
   return self:connect(sa)
end

function listen_unix(file, args)
   args = args or {}
   local s = socket('unix', args.stype or "stream", args.protocol)
   s:listen_unix(file)
   if args.ephemeral then
      local parent_close = s.close
      function s:close()
         parent_close(s)
         S.unlink(file)
      end
   end
   return s
end

function connect_unix(file, stype, protocol)
   local s = socket('unix', stype or 'stream', protocol)
   return s:connect_unix(file)
end

function connect_netlink(typ, groups)
   local tp = assert(S.c.NETLINK[typ])
   local s  = socket('netlink', 'raw', tp)
   return s:listen_netlink(groups)
end

function Socket:close()
   if self.fd then self.fd:close() end
   self.fd = nil
end

function selftest()
   print('selftest: lib.stream.socket')
   local shm = require('core.shm')

   local sockname = shm.root..'/'..tostring(S.getpid())..'/test-socket'
   S.unlink(sockname)

   local server = listen_unix(sockname)
   local client = connect_unix(sockname)
   local peer = server:accept()

   local message = "hello, world\n"
   client:write(message)
   client:flush_output()
   local message2 = peer:read_some_chars()
   assert(message == message2)
   client:close()
   assert(peer:read_some_chars() == nil)
   peer:close()

   server:close()

   S.unlink(sockname)

   print('selftest: ok')
end
