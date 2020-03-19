#!/usr/bin/env lua5.3

local my_config = require("my_config")
local circle = require("circle")
local cqueues = require("cqueues")
local condition = require("cqueues.condition")

local queue = cqueues.new()

math.randomseed(os.time())
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
client:hook("stop", function(self, death_reason)
	print(death_reason)
	shutdown_cond:signal()
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
