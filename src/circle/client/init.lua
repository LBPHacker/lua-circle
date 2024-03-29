local proto = require("circle.proto")
local util = require("circle.util")
local cqueues = require("cqueues")
local promise = require("cqueues.promise")
local errno = require("cqueues.errno")
local socket = require("cqueues.socket")
local ssl = require("openssl.ssl")

local client_i = {}
local client_m = { __index = client_i }

function client_i:last_prefix()
	return self.last_prefix_
end

function client_i:channel(chan)
	assert(type(chan) == "string", "argument #1 is not a string")
	return self.channels_[self:lower(chan)]
end

function client_i:channels()
	return next, self.channels_
end

function client_i:user(nick)
	assert(type(nick) == "string", "argument #1 is not a string")
	return self.users_[self:lower(nick)]
end

function client_i:users()
	return next, self.users_
end

function client_i:inick()
	return self.inick_
end

function client_i:nick(nick)
	if nick == nil then
		return self.nick_
	end
	return self:set_nick(nick)
end

function client_i:die_(message)
	if self.status_ ~= "dead" then
		if self.debug_ then
			self.debug_("die", message)
		end
		self.status_ = "dead"
		self.death_reason_ = message
		self:close_()
		self:trigger_die_()
	end
end

function client_i:proto_error_(message)
	self:die_("protocol error: " .. message)
end

function client_i:status()
	return self.status_
end

function client_i:hook(name, func)
	assert(type(name) == "string", "argument #1 is not a string")
	assert(type(func) == "function", "argument #2 is not a function")
	assert(self.hooks_[name], "no such hook")
	self.hooks_[name][func] = true
end

function client_i:unhook(name, func)
	assert(type(name) == "string", "argument #1 is not a string")
	assert(type(func) == "function", "argument #2 is not a function")
	assert(self.hooks_[name], "no such hook")
	self.hooks_[name][func] = nil
end

function client_i:lower(str)
	return proto.lower(self.casemapping_, str)
end

local hook_names = {}
local function define_hook(name)
	hook_names[name] = true
	client_i["trigger_" .. name .. "_"] = function(self, ...)
		for hook in pairs(self.hooks_[name]) do
			hook(...)
		end
	end
end

define_hook("pre_command_")

define_hook("user_appear")
define_hook("user_disappear")
define_hook("other_join")
define_hook("self_join")
define_hook("other_part")
define_hook("self_part")
define_hook("other_nick")
define_hook("self_nick")
define_hook("command")
define_hook("unknown_command")
define_hook("self_privmsg")
define_hook("channel_privmsg")
define_hook("unknown_privmsg")
define_hook("self_notice")
define_hook("channel_notice")
define_hook("unknown_notice")
define_hook("channel_topic")
define_hook("die")
define_hook("other_quit")
define_hook("self_quit")
define_hook("other_kick")
define_hook("self_kick")
define_hook("proxy_reconnect")

function client_i:check_command_(command, ...)
	if command:find("^%d+$") then
		local client = ...
		if not client then
			self:proto_error_(command .. " command with no client specified")
			return
		end
		if self:lower(client) ~= self.inick_ then
			return false
		end
	end
	local ok, err = proto.check_command(command, ...)
	if not ok then
		self:proto_error_(err)
		return
	end
	return true
end

function client_i:read_()
	local socket = self.socket_
	local buf = ""
	while self.status_ ~= "dead" do
		local data, err = socket:read(-self.read_size_)
		if data then
			buf = buf .. data
			while true do
				local _, line_ends_at = buf:find("\r\n")
				if not line_ends_at then
					break
				end
				if line_ends_at > self.message_size_limit_ then
					self:proto_error_("message size limit exceeded")
					break
				end
				local line = buf:sub(1, line_ends_at - 2)
				if self.debug_ then
					self.debug_(line)
				end
				if line:find("[\0\r\n]") then
					self:proto_error_("invalid octets in stream")
					break
				end
				local command, params, prefix = proto.parse_line(line)
				if not command then
					self:proto_error_("failed to parse line: " .. params)
					break
				end
				self:process_prefix_(prefix)
				if self.debug_ then
					self.debug_(self.last_prefix_.inick, command, table.unpack(params))
				end
				local process = self:check_command_(command, table.unpack(params))
				if self.status_ == "dead" then
					break
				end
				if process then
					self:trigger_pre_command__(command, table.unpack(params))
					if self.status_ == "dead" then
						break
					end
					self:trigger_command_(command, table.unpack(params))
				end
				buf = buf:sub(line_ends_at + 1)
			end
		elseif err ~= errno.EAGAIN then
			if socket:eof("r") then
				self:proto_error_("connection closed")
			else
				self:proto_error_("read failed with code " .. err)
			end
		end
	end
	socket:close()
end

function client_i:close_()
	if self.socket_ then
		-- if self.debug_ then
		-- 	self.debug_("closed", debug.traceback())
		-- end
		self.socket_:flush("n", self.sendq_flush_timeout_)
		self.socket_:shutdown("rw") -- * Also shuts down the read_ loop.
		self.socket_ = nil
	end
end

function client_i:process_prefix_(prefix)
	self.last_prefix_.raw = prefix or false
	if prefix then
		local nick_and_user, host = prefix:match("^(.*)@([^@]+)$")
		nick_and_user = nick_and_user or prefix
		local nick, user = nick_and_user:match("^(.*)!([^!]+)$")
		nick = nick or nick_and_user
		local inick = nick and self:lower(nick) or false
		self.last_prefix_.inick = inick
		self.last_prefix_.nick = nick or false
		self.last_prefix_.user = user or false
		self.last_prefix_.host = host or false
		self.last_prefix_.is_self = inick == self.inick_
	else
		self.last_prefix_.inick = false
		self.last_prefix_.nick = false
		self.last_prefix_.user = false
		self.last_prefix_.host = false
		self.last_prefix_.is_self = false
	end
end

function client_i:prefix_is_self()
	return self.last_prefix_.is_self
end

function client_i:is_self(nick)
	return self:lower(nick) == self.inick_
end

local channel_i = {}
local channel_m = { __index = channel_i }

function channel_i:users()
	return next, self.users_
end

function channel_i:valid()
	return self.valid_
end

function channel_i:name()
	return self.name_
end

function channel_i:iname()
	return self.iname_
end

function channel_i:topic()
	return self.topic_
end

local user_i = {}
local user_m = { __index = user_i }

function user_i:channels()
	return next, self.channels_
end

function user_i:valid()
	return self.valid_
end

function user_i:nick()
	return self.nick_
end

function user_i:inick()
	return self.inick_
end

function client_i:remove_user_from_channel_(nick, chan, reason, message)
	local inick = self:lower(nick)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	local user = self.users_[inick]
	if reason == "other_part" then
		if not user then
			return nil, "PART command from unknown user"
		end
		self:trigger_other_part_(user, channel, message)
	end
	if reason == "other_kick" then
		if not user then
			return nil, "KICK command pertaining to unknown user"
		end
		self:trigger_other_kick_(user, channel, message)
	end
	user.channels_[channel] = nil
	channel.users_[user] = nil
	if not next(user.channels_) then
		self:trigger_user_disappear_(user)
		self.users_[inick] = nil
	end
	return true
end

function client_i:add_user_to_channel_(nick, chan, reason)
	local inick = self:lower(nick)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	local user = self.users_[inick]
	if not user then
		user = setmetatable({
			nick_ = nick,
			inick_ = inick,
			valid_ = true,
			channels_ = {},
		}, user_m)
		self.users_[inick] = user
		self:trigger_user_appear_(user)
	end
	if reason == "other_join" then
		if user.channels_[channel] then
			return nil, "JOIN command from user already present"
		end
	end
	user.channels_[channel] = true
	channel.users_[user] = true
	if reason == "other_join" then
		self:trigger_other_join_(user, channel)
	end
	return true
end

function client_i:handle_join_(chan)
	local ichan = self:lower(chan)
	if self.last_prefix_.is_self then
		if self.channels_[ichan] then
			return nil, "JOIN command with channel already joined"
		end
		local channel = setmetatable({
			name_ = chan,
			iname_ = ichan,
			valid_ = true,
			users_ = {},
			init_done_ = false,
			topic_ = false,
		}, channel_m)
		self.channels_[ichan] = channel
	else
		local ok, err = self:add_user_to_channel_(self.last_prefix_.nick, chan, "other_join")
		if not ok then
			return nil, err
		end
	end
	return true
end

function client_i:handle_quit_(message)
	local user = self.users_[self.last_prefix_.inick]
	if not user then
		return nil, "QUIT command from unknown user"
	end
	while next(user.channels_) do
		self:remove_user_from_channel_(self.last_prefix_.nick, next(user.channels_).name_, "other_quit")
	end
	self:trigger_other_quit_(user, message)
	return true
end

function client_i:handle_kick_(chan, nick, message)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if self:is_self(nick) then
		if not channel then
			return nil, "KICK command with channel not yet joined"
		end
		self:trigger_self_kick_(channel, message)
		while next(channel.users_) do
			self:remove_user_from_channel_(next(channel.users_).nick, chan, "self_kick")
		end
		self.channels_[ichan] = nil
		channel.valid_ = false
	else
		local ok, err = self:remove_user_from_channel_(nick, chan, "other_kick", message)
		if not ok then
			return nil, err
		end
	end
	return true
end

function client_i:handle_part_(chan, message)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if self.last_prefix_.is_self then
		if not channel then
			return nil, "PART command with channel not yet joined"
		end
		self:trigger_self_part_(channel, message)
		while next(channel.users_) do
			self:remove_user_from_channel_(next(channel.users_).nick, chan, "self_part")
		end
		self.channels_[ichan] = nil
		channel.valid_ = false
	else
		local ok, err = self:remove_user_from_channel_(self.last_prefix_.nick, chan, "other_part", message)
		if not ok then
			return nil, err
		end
	end
	return true
end

function client_i:handle_RPL_WELCOME_()
	if self.got_welcome_ then
		self:trigger_proxy_reconnect_()
		self:quit()
	else
		self.got_welcome_ = true
	end
	return true
end

function client_i:handle_RPL_NAMREPLY_(visibility, chan, list)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if not channel then
		return nil, "RPL_NAMREPLY command with channel not yet joined"
	end
	if not channel.namreply_ then
		channel.namreply_ = {}
	end
	table.insert(channel.namreply_, list)
	return true
end

function client_i:handle_privmsg_(target, message)
	if self:is_self(target) then
		self:trigger_self_privmsg_(message)
	else
		local ichan = self:lower(target)
		local channel = self.channels_[ichan]
		if channel then
			self:trigger_channel_privmsg_(channel, message)
		else
			self:trigger_unknown_privmsg_(target, message)
		end
	end
	return true
end

function client_i:handle_notice_(target, message)
	if self:is_self(target) then
		self:trigger_self_notice_(message)
	else
		local ichan = self:lower(target)
		local channel = self.channels_[ichan]
		self:trigger_channel_notice_(channel, message)
		if channel then
			self:trigger_channel_notice_(channel, message)
		else
			self:trigger_unknown_notice_(target, message)
		end
	end
	return true
end

function client_i:handle_RPL_ENDOFNAMES_(chan)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if not channel then
		return nil, "RPL_ENDOFNAMES command with channel not yet joined"
	end
	if not channel.namreply_ then
		channel.namreply_ = {}
	end
	local inicks = {}
	for entry in table.concat(channel.namreply_, " "):gmatch("[^ ]+") do
		local status = self.names_prefixes_[entry:sub(1, 1)]
		if status then
			entry = entry:sub(2)
		end
		local nick = entry
		if not util.valid_nick(nick) then
			return nil, "RPL_NAMREPLY command with invalid user list"
		end
		local inick = self:lower(nick)
		if inicks[inick] then
			return nil, "RPL_NAMREPLY command with duplicate entries"
		end
		inicks[inick] = {
			status = status or false,
			nick = nick,
		}
	end
	if channel.init_done_ then
		for inick in pairs(inicks) do
			if not channel.users_[inick] then
				return nil, "RPL_NAMREPLY inconsistent with internal state"
			end
		end
		for inick in pairs(channel.users_) do
			if not inicks[inick] then
				return nil, "RPL_NAMREPLY inconsistent with internal state"
			end
		end
	else
		for inick, info in pairs(inicks) do
			self:add_user_to_channel_(info.nick, chan, "self_join")
		end
		channel.init_done_ = true
		self:trigger_self_join_(channel)
	end
	channel.namreply_ = nil
	return true
end

function client_i:handle_RPL_WHOISUSER_(nick, user, host, _, real)
	local inick = self:lower(nick)
	if self.whois_[inick] then
		self.whois_[inick].user = user
		self.whois_[inick].iuser = self:lower(user)
		self.whois_[inick].host = host
		self.whois_[inick].ihost = self:lower(host)
		self.whois_[inick].real = real
	end
	return true
end

function client_i:handle_RPL_WHOISSECURE_(nick)
	local inick = self:lower(nick)
	if self.whois_[inick] then
		self.whois_[inick].secure = true
	end
	return true
end

function client_i:handle_RPL_WHOISLOGGEDIN_(nick, account)
	local inick = self:lower(nick)
	if self.whois_[inick] then
		self.whois_[inick].account = account
		self.whois_[inick].iaccount = self:lower(account)
	end
	return true
end

function client_i:handle_RPL_NOTOPIC_(chan)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if not channel then
		return nil, "RPL_NOTOPIC command with channel not yet joined"
	end
	channel.topic_ = false
	if channel.init_done_ then
		self:trigger_channel_topic_(channel)
	end
	return true
end

function client_i:handle_RPL_TOPIC_(chan, topic)
	local ichan = self:lower(chan)
	local channel = self.channels_[ichan]
	if not channel then
		return nil, "RPL_TOPIC command with channel not yet joined"
	end
	channel.topic_ = topic
	if channel.init_done_ then
		self:trigger_channel_topic_(channel)
	end
	return true
end

function client_i:raw(line)
	if line:sub(-2, -1) == "\r\n" then
		line = line:sub(1, -3)
	end
	if line:find("[\0\r\n]") then
		return nil, "malformed line"
	end
	return self:send_line_(line .. "\r\n")
end

function client_i:handle_ping_(server, server2)
	if server2 then
		self:send_("pong", { server }, server2)
	else
		self:send_("pong", {}, server)
	end
	return true
end

function client_i:handle_nick_(nick)
	local inick = self:lower(nick)
	if self.last_prefix_.is_self then
		local prev = self.nick_
		self.nick_ = nick
		self.inick_ = inick
		self:trigger_self_nick_(prev)
	else
		local prev = self.last_prefix_.inick
		if not self.users_[prev] then
			return nil, "NICK command from unknown user"
		end
		local user = self.users_[prev]
		user.nick_ = nick
		user.inick_ = inick
		self.users_[prev] = nil
		self.users_[inick] = user
		self:trigger_other_nick_(user, prev)
	end
	return true
end

local named_command_handlers = {}
local numeric_command_handlers = {}
for key, value in pairs(client_i) do
	local command = key:match("^handle_(.*)_$")
	if command then
		if proto.msgno[command] then
			numeric_command_handlers[proto.msgno[command]] = value
		else
			named_command_handlers[command] = value
		end
	end
end

function client_i:forward_command_(command, first, ...)
	local named_handler = named_command_handlers[command]
	if named_handler then
		return named_handler(self, first, ...)
	end
	local numeric_handler = numeric_command_handlers[command]
	if numeric_handler then
		return numeric_handler(self, ...)
	end
	self:trigger_unknown_command_(command, first, ...)
	return true
end

function client_i:wait_for_response_(done, check)
	local die_hook, command_hook
	function die_hook()
		done:set(true, false, "cancelled: " .. self.death_reason_)
		self:unhook("die", die_hook)
		self:unhook("command", command_hook)
	end
	function command_hook(command, ...)
		check(command, ...)
		if done:status() ~= "pending" then
			self:unhook("die", die_hook)
			self:unhook("command", command_hook)
		end
	end
	self:hook("die", die_hook)
	self:hook("command", command_hook)
end

function client_i:queue_1_join_(chan, key)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_channel(chan) and chan ~= "0", "argument #1 is invalid")
	assert(key == nil or util.valid_key(key), "argument #2 is invalid")
	local ichan = self:lower(chan)
	if self:channel(ichan) then
		return true
	end
	local done = promise.new()
	self:wait_for_response_(done, function(command, ...)
		repeat
			if command == "join" then
				if self.last_prefix_.is_self and self:channel(ichan) then
					done:set(true, true)
				end
			elseif command == proto.msgno.ERR_NOSUCHCHANNEL then
				done:set(true, false, "no such channel")
			elseif command == proto.msgno.ERR_TOOMANYCHANNELS then
				done:set(true, false, "would exceed channel limit")
			elseif command == proto.msgno.ERR_CHANNELISFULL then
				done:set(true, false, "channel is full")
			elseif command == proto.msgno.ERR_INVITEONLYCHAN then
				done:set(true, false, "invite-only channel")
			elseif command == proto.msgno.ERR_BANNEDFROMCHAN then
				done:set(true, false, "banned from channel")
			elseif command == proto.msgno.ERR_BADCHANNELKEY then
				done:set(true, false, "bad channel key")
			elseif command == proto.msgno.RPL_TRYAGAIN then
				local what = ...
				if what:lower() == "join" then
					done:set(true, false, "hit rate limit")
				end
			end
		until true
	end)
	local ok, err = self:multisend_({ { "join", { chan, key } } })
	if not ok then
		return nil, "send failed: " .. err
	end
	local ok, err = done:get()
	if not ok then
		return nil, err
	end
	return true
end

function client_i:queue_1_part_(chan, message)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_channel(chan), "argument #1 is invalid")
	assert(message == nil, util.valid_message(message), "argument #2 is invalid")
	local ichan = self:lower(chan)
	if not self:channel(ichan) then
		return true
	end
	local done = promise.new()
	self:wait_for_response_(done, function(command, ...)
		repeat
			if command == "part" then
				if self.last_prefix_.is_self and not self:channel(ichan) then
					done:set(true, true)
				end
			elseif command == proto.msgno.RPL_TRYAGAIN then
				local what = ...
				if what:lower() == "part" then
					done:set(true, false, "hit rate limit")
				end
			end
		until true
	end)
	local ok, err = self:multisend_({ { "part", { chan }, message } })
	if not ok then
		return nil, "send failed: " .. err
	end
	local ok, err = done:get()
	if not ok then
		return nil, err
	end
	return true
end

function client_i:queue_0_set_nick_(nick)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_nick(nick), "argument #1 is invalid")
	local inick = self:lower(nick)
	if self:inick() == inick then
		return true
	end
	local done = promise.new()
	self:wait_for_response_(done, function(command, ...)
		repeat
			if command == "nick" then
				if self.last_prefix_.is_self and self:inick() == inick then
					done:set(true, true)
				end
			elseif command == proto.msgno.ERR_NICKNAMEINUSE then
				done:set(true, false, "nick in use")
			elseif command == proto.msgno.ERR_UNAVAILRESOURCE then
				done:set(true, false, "unavailable resource")
			elseif command == proto.msgno.ERR_RESTRICTED then
				done:set(true, false, "restricted")
			elseif command == proto.msgno.ERR_ERRONEUSNICKNAME then
				done:set(true, false, "erroneous nick")
			elseif command == proto.msgno.ERR_NICKCOLLISION then
				done:set(true, false, "nick collision")
			elseif command == proto.msgno.RPL_TRYAGAIN then
				local what = ...
				if what:lower() == "nick" then
					done:set(true, false, "hit rate limit")
				end
			end
		until true
	end)
	local ok, err = self:multisend_({ { "nick", { nick } } })
	if not ok then
		return nil, "send failed: " .. err
	end
	local ok, err = done:get()
	if not ok then
		return nil, err
	end
	return true
end

function client_i:queue_1_whois_(nick)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_nick(nick), "argument #1 is invalid")
	local inick = self:lower(nick)
	local info = {}
	self.whois_[inick] = info
	local done = promise.new()
	self:wait_for_response_(done, function(command, ...)
		repeat
			if command == proto.msgno.RPL_ENDOFWHOIS then
				done:set(true, true)
			elseif command == proto.msgno.ERR_NOSUCHNICK then
				done:set(true, false, "no such nick")
			elseif command == proto.msgno.RPL_TRYAGAIN then
				local what = ...
				if what:lower() == "whois" then
					done:set(true, false, "hit rate limit")
				end
			end
		until true
	end)
	self.whois_[inick] = nil
	local ok, err = self:multisend_({ { "whois", { nick } } })
	if not ok then
		return nil, "send failed: " .. err
	end
	local ok, err = done:get()
	if not ok then
		return nil, err
	end
	return info
end

function client_i:queue_0_go_()
	if self.status_ ~= "ready" then
		return nil, "not ready"
	end
	self.status_ = "starting"
	local ok, err = pcall(function()
		-- * .connect may itself throw errors, hence the pcall+assert trickery.
		self.socket_ = assert(socket.connect({
			host = self.host_,
			port = self.port_,
			sendname = self.use_tls_,
		}))
		assert(self.socket_:connect())
	end)
	if not ok then
		self.status_ = "dead"
		return nil, "connect failed: " .. err
	end
	if self.use_tls_ then
		local ok, err = pcall(function()
			-- * :starttls may itself throw errors, hence the pcall+assert trickery.
			assert(self.socket_:starttls(ssl.new(self.tls_ctx_)))
		end)
		if not ok then
			self.status_ = "dead"
			return nil, "starttls failed: " .. err
		end
	end
	self.socket_:setmode("bn", "bn")
	self.socket_:onerror(function(_, _, code, _)
		return code
	end)
	util.cqueues_wrap(cqueues.running(), function()
		self:read_()
	end)
	self:hook("pre_command_", function(...)
		local ok, err = self:forward_command_(...)
		if not ok then
			self:proto_error_(err)
		end
	end)
	local done = promise.new()
	local function handle_response(command, ...)
		if command == proto.msgno.RPL_WELCOME then
			done:set(true, true)
		elseif command == proto.msgno.ERR_NICKNAMEINUSE then
			done:set(true, false, "nick in use")
		elseif command == proto.msgno.ERR_UNAVAILRESOURCE then
			done:set(true, false, "unavailable resource")
		elseif command == proto.msgno.ERR_RESTRICTED then
			done:set(true, false, "restricted")
		elseif command == proto.msgno.ERR_ERRONEUSNICKNAME then
			done:set(true, false, "erroneous nick")
		elseif command == proto.msgno.ERR_NICKCOLLISION then
			done:set(true, false, "nick collision")
		end
		if done:status() ~= "pending" then
			self:unhook("pre_command_", handle_response)
		end
	end
	self:hook("pre_command_", handle_response)
	do
		local batch = {
			{ "nick", { self.nick_ } },
			{ "user", { self.user_, "0", "*" }, self.real_ },
		}
		if self.pass_ then
			table.insert(batch, 1, { "pass", {}, self.pass_ })
		end
		local ok, err = self:multisend_(batch)
		if not ok then
			self.status_ = "dead"
			return nil, "send failed: " .. err
		end
	end
	local ok, err = done:get()
	if not ok then
		self:close_()
		self.status_ = "dead"
		return nil, err
	end
	self.status_ = "running"
	return true
end

function client_i:queue_0_quit_(message)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	self:trigger_self_quit_(message)
	self.status_ = "stopping"
	self:multisend_({ { "quit", {}, message or "bye" } })
	self:die_("quit")
	self.status_ = "dead"
	return true
end

function client_i:privmsg(target, message)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_target(target), "argument #1 is invalid")
	assert(util.valid_message(message), "argument #2 is invalid")
	local ok, err = self:multisend_({ { "privmsg", { target }, message } })
	if not ok then
		return nil, "send failed: " .. err
	end
	return true
end

function client_i:notice(target, message)
	if self.status_ ~= "running" then
		return nil, "not running"
	end
	assert(util.valid_target(target), "argument #1 is invalid")
	assert(util.valid_message(message), "argument #2 is invalid")
	local ok, err = self:multisend_({ { "notice", { target }, message } })
	if not ok then
		return nil, "send failed: " .. err
	end
	return true
end

function client_i:multisend_(batch)
	for i = 1, #batch do
		local ok, err = self:send_(table.unpack(batch[i]))
		if not ok then
			return nil, err
		end
	end
	return true
end

function client_i:send_line_(line)
	local ok, err = self.socket_:write(line)
	if not ok then
		if self.socket_:eof("w") then
			self:close_()
			return nil, "connection closed"
		else
			self:close_()
			return nil, "send failed with code " .. err
		end
	end
	if self.sendq_limit_ then
		local _, sendq = self.socket_:pending()
		if sendq > self.sendq_limit_ then
			self:close_()
			return nil, "send queue limit exceeded"
		end
	end
	return true
end

function client_i:send_(command, middles, trailing, prefix)
	if not self.socket_ then
		return nil, "socket gone"
	end
	local line, err = proto.build_line(self.message_size_limit_, command, middles, trailing, prefix)
	if not line then
		return nil, err
	end
	if self.debug_ then
		self.debug_(line)
	end
	return self:send_line_(line)
end

do
	local pfuncs = {}
	for key, value in pairs(client_i) do
		local key_params, name = key:match("^queue_(%d+)_(.*)_$")
		if key_params then
			key_params = tonumber(key_params)
			local function qfunc(self, ...)
				local params = { name, ... }
				local iparams = { name, ... }
				for i = 1, key_params do
					if type(params[i + 1]) ~= "string" then
						error("argument #" .. i .. " is not a string")
					end
					iparams[i + 1] = self:lower(iparams[i + 1])
				end
				local key = table.concat(iparams, " ")
				local prev = self.queues_[key]
				local curr = {
					params = params,
					prom = promise.new(),
				}
				self.queues_[key] = curr
				if prev then
					prev.next = self.queues_[key]
				else
					util.cqueues_wrap(cqueues.running(), function()
						local req = self.queues_[key]
						while req do
							req.prom:set(true, value(self, table.unpack(req.params, 2)))
							req = req.next
						end
						self.queues_[key] = nil
					end)
				end
				return curr.prom
			end
			pfuncs["p" .. name] = qfunc
			pfuncs[name] = function(...)
				return qfunc(...):get()
			end
		end
	end
	for key, value in pairs(pfuncs) do
		client_i[key] = value
	end
end

local function new(params)
	assert(type(params) == "table", "argument #1 is not a table")
	assert(util.valid_nick(params.nick), "nick is invalid")
	assert(util.valid_user(params.user), "user is invalid")
	assert(util.valid_pass(params.pass), "pass is invalid")
	assert(util.valid_host(params.host), "host is invalid")
	assert(util.valid_real(params.real), "real is invalid")
	assert(params.sendq_flush_timeout == nil or type(params.sendq_flush_timeout) == "number", "sendq_flush_timeout is not a number")
	assert(util.integer(params.port), "port is not an integer")
	assert(params.message_size_limit == nil or util.integer(params.message_size_limit), "message_size_limit is not an integer")
	assert(params.read_size_ == nil or util.integer(params.read_size), "read_size is not an integer")
	assert(params.sendq_limit == nil or util.integer(params.sendq_limit), "sendq_limit is not an integer")
	local cli = setmetatable({
		casemapping_ = proto.mappings["rfc1459-strict"],
		hooks_ = {},
		channels_ = {},
		users_ = {},
		status_ = "ready",
		nick_ = params.nick,
		user_ = params.user,
		pass_ = params.pass,
		host_ = params.host,
		port_ = params.port,
		real_ = params.real,
		use_tls_ = params.tls and true or false,
		tls_ctx_ = params.tls and params.tls_ctx or util.default_tls_context(),
		queues_ = {},
		message_size_limit_ = params.message_size_limit or 512,
		sendq_limit_ = params.sendq_limit,
		sendq_flush_timeout_ = params.sendq_flush_timeout or 1,
		read_size_ = params.read_size_ or 512,
		last_prefix_ = {},
		whois_ = {},
		debug_ = params.debug,
		names_prefixes_ = {
			[ "@" ] = "o",
			[ "+" ] = "v",
		},
	}, client_m)
	cli.inick_ = cli:lower(cli.nick_)
	for name in pairs(hook_names) do
		cli.hooks_[name] = {}
	end
	return cli
end

return {
	new = new,
}
