#!/usr/bin/env lua5.3

local my_config = require("my_config")
local circle = require("circle")
local cqueues = require("cqueues")
local condition = require("cqueues.condition")

local queue = cqueues.new()

local client = circle.client({
	host = my_config.host,
	port = my_config.port,
	nick = my_config.nick,
	real = my_config.real,
	user = my_config.user,
	pass = my_config.pass,
	tls = true,
	queue = queue
})

local shutdown_cond = condition.new()
client:hook("stop", function(self, stop_reason)
	if stop_reason then
		print("STOP: " .. stop_reason)
	end
	shutdown_cond:signal()
end)

client:hook("warn", function(self, warn_reason)
	print("WARN: " .. warn_reason)
end)

client:hook("self_join", function(self, channel)
	channel:set_who_tracking(true)
	print("enabled who-tracking on " .. channel:get_name())
end)

client:hook("privmsg", function(self, source, target, message)
	if self:is_self(target) then
		self:privmsg(source, message)
	elseif self:get_channel(target) then
		local nick = self:get_nick()
		local before, after = message:sub(1, #nick), message:sub(#nick + 1)
		if self:lower(before) == nick and after:find("^%W") then
			self:privmsg(target, source .. ": " .. after:match("^%W+(.-)$"))
		end
	end
end)

queue:wrap(function()
	client:connect()

	local stdin_pollable = { pollfd = 0, events = "r" }
	local func_env = setmetatable({ client = client }, { __index = _ENV })
	while client:get_status() == "running" do
		io.write("> ")
		io.flush()
		local ready = { assert(cqueues.poll(stdin_pollable, shutdown_cond)) }
		for ix = 1, #ready do
			if ready[ix] == stdin_pollable then
				local code = io.read()
				if code then
					local func, err = load(code, "=stdin", "t", func_env)
					if func then
						xpcall(func, function(err)
							print(err)
							print(debug.traceback())
						end)
					else
						print(err)
					end
				else
					client:quit()
				end
			end
		end
	end
end)

assert(queue:loop())
