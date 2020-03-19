local cqueues = require("cqueues")
local socket = require("cqueues.socket")
local condition = require("cqueues.condition")
local ssl = require("openssl.ssl")
local ssl_ctx = require("openssl.ssl.context")
local ssl_pkey = require("openssl.pkey")

local unpack = rawget(_G, "unpack") or table.unpack
local bit = rawget(_G, "bit") or rawget(_G, "bit32")

local casemappings = {}
do
	local casemappings_init = {
		["ascii"] = {
			upper = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ]==],
			lower = [==[abcdefghijklmnopqrstuvwxyz]==],
		},
		["rfc1459"] = {
			upper = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\~]==],
			lower = [==[abcdefghijklmnopqrstuvwxyz{}|^]==],
		},
		["rfc1459-strict"] = {
			upper = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\]==],
			lower = [==[abcdefghijklmnopqrstuvwxyz{}|]==],
		},
	}
	for name, mapping_init in pairs(casemappings_init) do
		assert(#mapping_init.lower == #mapping_init.upper)
		local lower = {}
		local upper = {}
		for ix = 1, #mapping_init.lower do
			lower[mapping_init.upper:sub(ix, ix)] = mapping_init.lower:sub(ix, ix)
			upper[mapping_init.lower:sub(ix, ix)] = mapping_init.upper:sub(ix, ix)
		end
		casemappings[name] = {
			lower = lower,
			upper = upper,
		}
	end
end

local function ok_nonempty_string(str)
	return type(str) == "string" and #str > 0
end
local function ok_nick(str)
	return type(str) == "string" and str:find("^[A-Za-z%[%]\\`_^{|}][A-Za-z0-9%[%]\\`_^{|}-]*$")
end
local function ok_cqueues_controller(cq)
	return cqueues.type(cq) == "controller"
end
local function ok_openssl_context(ctx)
	-- * TODO: find a good way to check this... openssl.ssl.context.type doesn't exist.
	return type(ctx) == "userdata"
end
local function ok_integer(num)
	return type(num) == "number" and math.floor(num) == num
end
local function ok_table(tbl)
	return type(tbl) == "table"
end
local function ok_string(str)
	return type(str) == "string"
end
local function ok_function(func)
	return type(func) == "function"
end
local function assert_param(ok, thing, name)
	return ok(thing) and thing or error("invalid " .. name, 3)
end
local function assert_param_default(ok, thing, name)
	return thing and (ok(thing) and thing or error("invalid " .. name, 3)) or nil
end

local client_i = {}
local client_m = { __index = client_i }

function client_i:get_lusers()
	return self.lusers_
end

function client_i:get_away()
	return self.away_
end

function client_i:get_isupport_tokens()
	return self.isupport_tokens_
end

function client_i:get_death_reason()
	return self.death_reason_
end

function client_i:get_all_death_reasons()
	return self.all_death_reasons_
end

function client_i:get_nick()
	return self.raw_nick_
end

function client_i:get_canonical_nick()
	return self.nick_
end

function client_i:get_status()
	return self.status_
end

function client_i:get_welcome()
	return self.welcome_
end

function client_i:lower(str)
	local lower = casemappings[self.casemapping_].lower
	local out = {}
	for letter in str:gmatch(".") do
		table.insert(out, lower[letter] or letter)
	end
	return table.concat(out)
end

function client_i:upper(str)
	local upper = casemappings[self.casemapping_].upper
	local out = {}
	for letter in str:gmatch(".") do
		table.insert(out, upper[letter] or letter)
	end
	return table.concat(out)
end

function client_i:send_(command, middles, trailing, prefix)
	if self.status_ ~= "running" then
		return
	end
	local data_parts = {}
	if prefix then
		table.insert(data_parts, ":")
		table.insert(data_parts, prefix)
		table.insert(data_parts, " ")
	end
	table.insert(data_parts, command)
	for ix = 1, #middles do
		table.insert(data_parts, " ")
		table.insert(data_parts, middles[ix])
	end
	if trailing then
		table.insert(data_parts, " :")
		table.insert(data_parts, trailing)
	end
	table.insert(data_parts, "\r\n")
	local data = table.concat(data_parts)
	if #data > self.message_size_limit_ then
		error("message size limit exceeded", 2)
	end
	local ok, err = self.client_socket_:write(data)
	if err then
		self:stop_("send failed: " .. tostring(err))
	end
end

function client_i:warn_incoming_(message)
	print(message)
end

local function handle_by_hook(command)
	client_i["handle_" .. command .. "_"] = function(self, ...)
		self:call_hook_(command, ...)
	end
end

function client_i:handle_001_(welcome) -- * RPL_WELCOME
	if self.registered_ then
		self:stop_("001 when already registered")
		return
	end
	if not welcome then
		self:stop_("001 with no welcome line")
		return
	end
	self.welcome_.welcome = welcome
	self.expecting_welcome_ = "002"
end

function client_i:handle_002_(yourhost) -- * RPL_YOURHOST
	if self.registered_ then
		self:stop_("002 when already registered")
		return
	end
	if not yourhost then
		self:stop_("002 with no yourhost line")
		return
	end
	self.welcome_.yourhost = yourhost
	self.expecting_welcome_ = "003"
end

function client_i:handle_003_(created) -- * RPL_CREATED
	if self.registered_ then
		self:stop_("003 when already registered")
		return
	end
	if not created then
		self:stop_("003 with no created line")
		return
	end
	self.welcome_.created = created
	self.expecting_welcome_ = "004"
end

function client_i:handle_004_(server_name, server_version, user_modes, channel_modes) -- * RPL_MYINFO
	if self.registered_ then
		self:stop_("004 when already registered")
		return
	end
	if not server_name then
		self:stop_("004 with no server name specified")
		return
	end
	if not server_version then
		self:stop_("004 with no server version specified")
		return
	end
	if not user_modes then
		self:stop_("004 with no user modes specified")
		return
	end
	if not channel_modes then
		self:stop_("004 with no channel modes specified")
		return
	end
	self.welcome_.server_name = server_name
	self.welcome_.server_version = server_version
	self.welcome_.user_modes = user_modes
	self.welcome_.channel_modes = channel_modes
	self.registered_ = true
	self.expecting_welcome_ = nil
	self.expecting_isupport_ = "005"
	self:call_hook_("welcome", self.welcome_)
end

function client_i:handle_005_(client, ...) -- * RPL_ISUPPORT, hopefully
	if not self.expecting_isupport_ then
		-- * TODO: handle these, stop when casemapping randomly changes, etc.
		self:warn_incoming_("005 when ISUPPORT tokens already received")
		return
	end
	if not client then
		self:stop_("005 with no client specified")
		return
	end
	local tokens = { ... }
	if #tokens == 0 then
		self:stop_("005 with no tokens specified")
		return
	end
	if #tokens == 1 then
		self:warn_incoming_("005 matching format of legacy RPL_BOUNCE")
		self.compat_flags_.no_isupport = true
		self:stop_("bounced: " .. tokens[1])
		return
	end
	for ix = 1, #tokens - 1 do -- * Last parameter is just a dummy.
		local parameter = tokens[ix]
		local value
		local erase = false
		if parameter:find("^%-") then
			parameter = parameter:sub(2)
			erase = true
		elseif parameter:find("=") then
			parameter, value = parameter:match("^([^=]*)=(.*)$")
		end
		local ok = true
		if not parameter:find("^[A-Z0-9]+$") or #parameter > 20 then
			self:stop_("005 token #" .. ix .. ": invalid parameter")
			ok = false
		end
		if value and not value:find("^[A-Za-z0-9!-/:-@[-`{-~]*$") then
			self:stop_("005 token #" .. ix .. ": invalid value")
			ok = false
		end
		if erase and value then
			self:stop_("005 token #" .. ix .. ": value specified despite erasure")
			ok = false
		end
		if ok then
			if erase then
				self.isupport_tokens_[parameter] = nil
			else
				self.isupport_tokens_[parameter] = value or true
			end
		end
	end
end

function client_i:handle_010_(...) -- * RPL_BOUNCE
	self:stop_("bounced: " .. table.concat({ ... }, " "))
end

handle_by_hook("250") -- * RPL_STATSDLINE, RPL_STATSCONN
handle_by_hook("301") -- * RPL_AWAY

function client_i:handle_251_(client, ...) -- * RPL_LUSERCLIENT
	self.lusers_.client = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_252_(client, ...) -- * RPL_LUSEROP
	self.lusers_.op = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_253_(client, ...) -- * RPL_LUSERUNKNOWN
	self.lusers_.unknown = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_254_(client, ...) -- * RPL_LUSERCHANNELS
	self.lusers_.channels = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_255_(client, ...) -- * RPL_LUSERME
	self.lusers_.me = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_263_(command) -- * RPL_TRYAGAIN
	if command == "nick" then
		if self.setting_nick_ then
			self.set_nick_error_ = 263
			self.setting_nick_:signal()
			self.setting_nick_ = nil
		else
			self:warn_incoming_("263 to nick while not setting nick")
		end
	elseif command == "away" then
		if self.setting_away_ then
			self.set_away_error_ = 263
			self.setting_away_:signal()
			self.setting_away_ = nil
		else
			self:warn_incoming_("263 to away while not setting away")
		end
	else
		self:warn_incoming_("263 to " .. command)
	end
end

function client_i:handle_265_(client, ...) -- * RPL_LOCALUSERS
	self.lusers_.loc = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_266_(client, ...) -- * RPL_GLOBALUSERS
	self.lusers_.glob = table.concat({ ... }, " ")
	self.handled_lusers_ = true
end

function client_i:handle_305_() -- * RPL_UNAWAY
	if self.away_ then
		self.away_ = nil
		self:call_hook_("unaway")
	else
		self:warn_incoming_("305 while not away")
	end
	if self.setting_away_ then
		self.setting_away_:signal()
		self.setting_away_ = nil
	end
end

function client_i:handle_306_() -- * RPL_NOWAWAY
	if self.away_ then
		self:warn_incoming_("306 while away")
	else
		self.away_ = self.away_message_sent_
		self.away_message_sent_ = nil
		self:call_hook_("away")
	end
	if self.setting_away_ then
		self.setting_away_:signal()
		self.setting_away_ = nil
	end
end

function client_i:handle_372_(motd_line) -- * RPL_MOTD
	if not self.receiving_motd_ then
		self:warn_incoming_("372 while not receiving motd")
		return
	end
	if not motd_line then
		self:warn_incoming_("372 with no motd line")
		return
	end
	table.insert(self.motd_, motd_line)
end

function client_i:handle_375_() -- * RPL_MOTDSTART
	if not self.expecting_motd_ then
		self:warn_incoming_("375 while not expecting motd")
		return
	end
	if self.receiving_motd_ then
		self:warn_incoming_("375 while already receiving motd")
		return
	end
	self.receiving_motd_ = true
	self.expecting_motd_ = nil
	self.motd_ = {}
end

function client_i:handle_376_() -- * RPL_ENDOFMOTD
	if not self.receiving_motd_ then
		self:warn_incoming_("376 while not receiving motd")
		return
	end
	self.receiving_motd_ = nil
end

function client_i:handle_422_() -- * ERR_NOMOTD
	if not self.expecting_motd_ then
		self:warn_incoming_("422 while not expecting motd")
		return
	end
	self.expecting_motd_ = nil
	self.motd_ = false
end

function client_i:handle_432_(command) -- * ERR_ERRONEUSNICKNAME
	if self.setting_nick_ then
		self.set_nick_error_ = 432
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	else
		self:warn_incoming_("432 while not setting nick")
	end
end

function client_i:handle_433_(command) -- * ERR_NICKNAMEINUSE
	if self.setting_nick_ then
		self.set_nick_error_ = 433
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	else
		self:warn_incoming_("433 while not setting nick")
	end
end

function client_i:handle_436_(command) -- * ERR_NICKCOLLISION
	self:stop_("nick collision")
end

function client_i:handle_437_(nick_or_channel) -- * ERR_UNAVAILRESOURCE
	if ok_nick(nick_or_channel) then
		-- * Assume it's a nick.
		if self.setting_nick_ then
			self.set_nick_error_ = 437
			self.setting_nick_:signal()
			self.setting_nick_ = nil
		else
			self:warn_incoming_("437 while not setting nick")
		end
	else
		-- * Assume it's a channel.
		-- * TODO: handle the channel case
	end
end

function client_i:handle_484_() -- * ERR_RESTRICTED
	-- * TODO: handle other cases
	if self.setting_nick_ then
		self.set_nick_error_ = 484
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	else
		self:warn_incoming_("484 while not setting nick")
	end
end

function client_i:handle_join_(channels)
	if not self.last_prefix_.nick then
		self:stop_("join with no nickname specified in prefix")
		return
	end
	if not channels then
		self:stop_("join with no channels specified")
		return
	end
	if self:prefix_is_self_() then
		for channel in channels:gmatch("[^,]+") do
			if self.channels_[channel] then
				self:warn_incoming_("channel " .. channel .. " in join list while already joined")
			else
				self.channels_[channel] = {}
				self:call_hook_("self_join", channel, self.channels_[channel])
			end
		end
	end
end

function client_i:handle_nick_(new)
	if not self.last_prefix_.nick then
		self:stop_("nick with no nickname specified in prefix")
		return
	end
	if not new then
		self:stop_("nick with no new nickname specified")
		return
	end
	if self:prefix_is_self_() then
		self:update_nick_(new)
	end
	if self.setting_nick_ then
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	end
end

function client_i:handle_part_(channels)
	if not self.last_prefix_.nick then
		self:stop_("part with no nickname specified in prefix")
		return
	end
	if not channels then
		self:stop_("part with no channels specified")
		return
	end
	if self:prefix_is_self_() then
		for channel in channels:gmatch("[^,]+") do
			if not self.channels_[channel] then
				self:warn_incoming_("channel " .. channel .. " in part list while not joined")
			else
				self:call_hook_("self_part", channel, self.channels_[channel])
				self.channels_[channel] = nil
			end
		end
	end
end

function client_i:handle_ping_(server, server2)
	if not server then
		self:stop_("ping with no server specified")
		return
	end
	self:send_("pong", { server, server2 })
end

function client_i:pre_handler_(command) -- * Used for edge-triggering.
	if self.expecting_welcome_ and command ~= self.expecting_welcome_ then
		self:stop_("bad welcome sequence: expected " .. self.expecting_welcome_ .. ", got " .. command)
		self.expecting_welcome_ = nil
	end
	if self.expecting_isupport_ and command ~= self.expecting_isupport_ then
		self.expecting_isupport_ = nil
		if not next(self.isupport_tokens_) then
			-- * TODO: handle this somehow
			self:warn_incoming_("server sent no ISUPPORT tokens")
			self.compat_flags_.no_isupport = true
		end
		self:process_isupport_()
	end
end

function client_i:post_handler_(command) -- * Used for edge-triggering.
	if self.receiving_lusers_ and not self.handled_lusers_ then
		self:call_hook_("lusers", self.lusers_)
	end
	self.receiving_lusers_ = self.handled_lusers_
	self.handled_lusers_ = nil
end

function client_i:dispatch_()
	local socket_pollable = { pollfd = self.client_socket_:pollfd(), events = "r" }
	while self.status_ == "running" do
		local ready = assert(cqueues.poll(socket_pollable, self.stopping_cond_))
		-- * Since we exit the loop immediately if self.stopping_cond_ is signalled,
		--   it's okay to compare ready only with socket_pollable.
		if ready == socket_pollable then
			-- * self.client_socket_ is in "tl" mode by default; read a line.
			local line_without_crlf, err = self.client_socket_:read()
			if line_without_crlf then
				self:process_line_(line_without_crlf)
			else
				self:stop_("read failed: " .. tostring(err))
			end
		end
	end
end

function client_i:prefix_is_self_()
	return self.last_prefix_.nick == self.nick_
end

function client_i:parse_line_(line_without_crlf)
	if line_without_crlf:find("[^\1-\255]") then
		return
	end
	local command, prefix
	local params = {}
	do
		local rest
		prefix, rest = line_without_crlf:match("^:([^ ]+) (.*)$")
		if prefix then
			line_without_crlf = rest
		end
	end
	do
		local rest
		command, rest = line_without_crlf:match("^(%d%d%d)(.*)$")
		if not command then
			command, rest = line_without_crlf:match("^([A-Za-z]+)(.*)$")
		end
		if not command then
			return
		end
		line_without_crlf = rest
	end
	while #params < 14 do
		local param, rest = line_without_crlf:match("^ ([^: ][^ ]*)(.*)$")
		if not param then
			break
		end
		table.insert(params, param)
		line_without_crlf = rest
	end
	do
		local trailing = line_without_crlf:match(#params == 14 and "^ :?(.*)$" or "^ :(.*)$")
		if trailing then
			table.insert(params, trailing)
		end
		line_without_crlf = ""
	end
	if line_without_crlf ~= "" then
		return
	end
	return command:lower(), params, prefix
end

function client_i:process_line_(line_without_crlf)
	local command, params, prefix = self:parse_line_(line_without_crlf)
	if command then
		self:process_prefix_(prefix)
		self:pre_handler_(command)
		local handler = self["handle_" .. command .. "_"]
		if handler then
			handler(self, unpack(params))
		else
			local quoted_params = {}
			for ix = 1, #params do
				table.insert(quoted_params, ("%q"):format(params[ix]))
			end
			self:warn_incoming_(("unhandled command: %s: %s %s"):format(prefix or "?", command, table.concat(quoted_params, " ")))
		end
		self:post_handler_(command)
	end
end

function client_i:process_prefix_(prefix)
	self.last_prefix_.raw = prefix or false
	if prefix then
		local nick_and_user, host = prefix:match("^(.*)@([^@]+)$")
		nick_and_user = nick_and_user or prefix
		local nick, user = nick_and_user:match("^(.*)!([^!]+)$")
		nick = nick or nick_and_user
		self.last_prefix_.nick = nick and self:lower(nick) or false
		self.last_prefix_.user = user or false
		self.last_prefix_.host = host or false
	else
		self.last_prefix_.nick = false
		self.last_prefix_.user = false
		self.last_prefix_.host = false
	end
end

function client_i:process_isupport_()
	if self.isupport_tokens_.CASEMAPPING then
		if not casemappings[self.isupport_tokens_.CASEMAPPING] then
			self:stop_("unknown casemapping " .. self.isupport_tokens_.CASEMAPPING)
			return
		end
		local old_nick = self.nick_
		self.casemapping_ = self.isupport_tokens_.CASEMAPPING
		if self:lower(self.raw_nick_) ~= old_nick then
			self:update_nick_(self.raw_nick_)
		end
	else
		self:warn_incoming_("no CASEMAPPING ISUPPORT token received, not changing currently effective casemapping " .. self.casemapping_)
	end
	self:call_hook_("isupport", self.isupport_tokens_)
end

do
	local error_messages = {
		[263] = "rate-limited",
		[432] = "erroneous nick",
		[433] = "nick already in use",
		[437] = "nick temporarily unavailable",
		[484] = "connection restricted",
	}

	function client_i:set_nick(new_in)
		self:assert_chat_phase_()
		if self.setting_nick_ then
			error("already setting nick", 2)
		end
		local new = assert_param(ok_nick, new_in, "nick")
		if self.raw_nick_ == new then
			return true
		end
		self.setting_nick_ = condition.new()
		self:send_("nick", { new })
		self.setting_nick_:wait() -- * self.setting_nick_ gets nil'd by the time this returns.
		local set_nick_error = self.set_nick_error_
		self.set_nick_error_ = nil
		if set_nick_error then
			return nil, error_messages[set_nick_error], set_nick_error
		end
		return true
	end
end

do
	local error_messages = {
		[263] = "rate-limited",
	}

	function client_i:set_away(message_in)
		self:assert_chat_phase_()
		if self.setting_away_ then
			error("already setting away", 2)
		end
		local message = assert_param_default(ok_string, message_in, "message") or self.default_away_message_
		if message == self.away_ then
			return true
		end
		self.setting_away_ = condition.new()
		self.away_message_sent_ = message
		self:send_("away", {}, message)
		self.setting_away_:wait() -- * self.setting_away_ gets nil'd by the time this returns.
		local set_away_error = self.set_away_error_
		self.set_away_error_ = nil
		if set_away_error then
			return nil, error_messages[set_away_error], set_away_error
		end
		return true
	end

	function client_i:unset_away()
		if not self.away_ then
			return true
		end
		self:assert_chat_phase_()
		if self.setting_away_ then
			error("already setting away", 2)
		end
		self.setting_away_ = condition.new()
		self:send_("away", {})
		self.setting_away_:wait() -- * self.setting_away_ gets nil'd by the time this returns.
		local set_away_error = self.set_away_error_
		self.set_away_error_ = nil
		if set_away_error then
			return nil, error_messages[set_away_error], set_away_error
		end
		return true
	end
end

function client_i:update_nick_(new)
	self.raw_nick_ = new
	self.nick_ = self:lower(new)
	self:call_hook_("self_nick", self.raw_nick_, self.nick_)
end

function client_i:assert_chat_phase_()
	if self.status_ ~= "running" then
		error("not running", 3)
	end
	if not self.registered_ then
		error("not yet registered", 3)
	end
end

function client_i:privmsg(target_in, message_in)
	self:assert_chat_phase_()
	local target = assert_param(ok_nonempty_string, target_in, "target")
	local message = assert_param(ok_string, message_in, "message")
	self:send_("privmsg", { target }, message)
end

function client_i:notice(target_in, message_in)
	self:assert_chat_phase_()
	local target = assert_param(ok_nonempty_string, target_in, "target")
	local message = assert_param(ok_string, message_in, "message")
	self:send_("notice", { target }, message)
end

function client_i:quit(message_in)
	local message = assert_param_default(ok_string, message_in, "message") or self.default_quit_message_
	self:send_("quit", {}, message)
end

function client_i:stop_(death_reason)
	if death_reason then
		if not self.all_death_reasons_ then
			self.all_death_reasons_ = {}
		end
		table.insert(self.all_death_reasons_, death_reason)
	end
	if self.status_ ~= "dead" then
		self:call_hook_("stop", death_reason)
		self.status_ = "dead"
		self.death_reason_ = death_reason
		self.stopping_cond_:signal()
	end
end

function client_i:hook(name_in, func_in)
	local name = assert_param(ok_string, name_in, "name")
	local func = assert_param(ok_function, func_in, "func")
	if not self.hooks_[name] then
		self.hooks_[name] = {}
	end
	self.hooks_[name][func] = true
end

function client_i:unhook(name_in, func_in)
	local name = assert_param(ok_string, name_in, "name")
	local func = assert_param(ok_function, func_in, "func")
	self.hooks_[name][func] = nil
	if not next(self.hooks_[name]) then
		self.hooks_[name] = nil
	end
end

function client_i:call_hook_(name, ...)
	local hooks = self.hooks_[name]
	if hooks then
		for hook in pairs(hooks) do
			hook(self, ...)
		end
	end
end

function client_i:disconnect_()
	self.client_socket_:close()
end

function client_i:register_()
	self:send_("pass", {}, self.pass_)
	self:send_("nick", { self.raw_nick_ })
	self:send_("user", { self.user_, "0", "*" }, self.real_)
	self.expecting_welcome_ = "001"
end

function client_i:connect()
	assert(self.status_ == "ready", "status ~= ready")
	self.status_ = "running"
	self.connecting_ = true
	self.stopping_cond_ = condition.new()
	self.client_socket_ = socket.connect({
		host = self.host_,
		port = self.port_,
		sendname = self.use_tls_,
	})
	do
		local ok, err = self.client_socket_:connect() -- * Actually wait until connection is established.
		if not ok then
			self:stop_("connect failed: " .. tostring(err))
			return false
		end
	end
	if self.use_tls_ then
		local ok, err = pcall(function()
			-- * :starttls may itself throw errors, hence the pcall+assert trickery.
			assert(self.client_socket_:starttls(ssl.new(self.tls_ctx_)))
		end)
		if not ok then
			self:stop_("starttls failed: " .. tostring(err))
			return false
		end
	end
	self.connecting_ = false
	self.queue_:wrap(function()
		self:register_()
	end)
	self.queue_:wrap(function()
		self:dispatch_()
		self:disconnect_()
	end)
	return true
end

local function make_tls_context()
	local ctx = ssl_ctx.new("TLS", false)
	ctx:setCipherList(table.concat({
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"ECDHE-ECDSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-AES256-SHA384",
		"ECDHE-RSA-AES256-SHA384",
		"ECDHE-ECDSA-AES128-SHA256",
		"ECDHE-RSA-AES128-SHA256",
	}, ":"))
	ctx:setOptions(bit.bor(
		ssl_ctx.OP_NO_COMPRESSION,
		ssl_ctx.OP_SINGLE_ECDH_USE,
		ssl_ctx.OP_NO_SSLv2,
		ssl_ctx.OP_NO_SSLv3
	))
	ctx:setEphemeralKey(ssl_pkey.new({
		type = "EC",
		curve = "prime256v1"
	}))
	ctx:getStore():addDefaults()
	ctx:setVerify(ssl_ctx.VERIFY_PEER)
	return ctx
end

local function make_client(params_in)
	local params = assert_param(ok_table, params_in, "params")
	local client = setmetatable({
		host_ = assert_param(ok_nonempty_string, params.host, "host"),
		port_ = assert_param(ok_integer, params.port, "port"),
		user_ = assert_param(ok_nonempty_string, params.user, "user"),
		raw_nick_ = assert_param(ok_nonempty_string, params.nick, "nick"),
		pass_ = assert_param(ok_nonempty_string, params.pass, "pass"),
		real_ = assert_param(ok_nonempty_string, params.real, "real"),
		status_ = "ready",
		use_tls_ = params.tls and true or false,
		tls_ctx_ = params.tls and (assert_param_default(ok_openssl_context, params.tls_ctx, "tls_ctx") or make_tls_context()),
		queue_ = assert_param_default(ok_cqueues_controller, params.queue, "queue") or cqueues.new(),
		message_size_limit_ = assert_param_default(ok_integer, params.message_size_limit, "message_size_limit") or 512,
		default_quit_message_ = "quit",
		default_away_message_ = "away",
		expecting_motd_ = true,
		hooks_ = {},
		compat_flags_ = {},
		isupport_tokens_ = {},
		lusers_ = {},
		welcome_ = {},
		last_prefix_ = {},
		channels_ = {},
		casemapping_ = "rfc1459-strict",
	}, client_m)
	client.nick_ = client:lower(client.raw_nick_)
	return client
end

return {
	client = make_client
}
