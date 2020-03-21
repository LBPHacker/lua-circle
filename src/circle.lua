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
-- * The folowing ok_* functions aren't actually enough to validate strings
--   on the semantics level, but they're enough to validate them on the protocol
--   level. If we send strings as parameters deemed valid by these, we'll at
--   least get real errors back instead of the server cutting us off due to
--   'not being able to speak IRC'.
local function ok_nick(str)
	return type(str) == "string" and str:find("^[A-Za-z%[%]\\`_^{|}][A-Za-z0-9%[%]\\`_^{|}-]*$")
end
local function ok_user(str)
	return type(str) == "string" and str:find("^[\1-\9\11-\12\14-\31\33-\63\65-\255]+$")
end
local function ok_channel(str)
	return type(str) == "string" and str:find("^[#+!&][\1-\7\8-\9\11-\12\14-\31\33-\43\45-\57\59-\255]+$")
end
local function ok_nick_or_channel(str)
	return ok_nick(str) or ok_channel(str)
end

local user_i = {}
local user_m = { __index = user_i }

function user_i:get_name()
	return self.name_
end

function user_i:get_raw_name()
	return self.raw_name_
end

local channel_i = {}
local channel_m = { __index = channel_i }

function channel_i:get_name()
	return self.name_
end

function channel_i:get_raw_name()
	return self.raw_name_
end

function channel_i:get_status()
	return self.status_
end

function channel_i:get_topic()
	return self.topic_, self.topic_by_, self.topic_at_
end

function channel_i:get_highest_modes()
	return self.highest_modes_
end

function channel_i:get_users()
	return self.users_
end

local client_i = {}
local client_m = { __index = client_i }

function client_i:get_lusers()
	return self.lusers_
end

function client_i:get_users_in_channels()
	return self.users_in_channels_
end

function client_i:get_away()
	return self.away_
end

function client_i:get_isupport_tokens()
	return self.isupport_tokens_
end

function client_i:get_stop_reason()
	return self.stop_reason_
end

function client_i:get_all_stop_reasons()
	return self.all_stop_reasons_
end

function client_i:get_raw_nick()
	return self.raw_nick_
end

function client_i:get_nick()
	return self.nick_
end

function client_i:get_channels()
	return self.channels_
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
	-- * TODO: parameter checking
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

function client_i:warn_(message)
	self:call_hook_("warn", message)
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
	self.welcome_ = {}
	self.welcome_.welcome = welcome
	self.registered_ = true
	self:call_hook_("register")
end

function client_i:handle_002_(yourhost) -- * RPL_YOURHOST
	if not self.welcome_ then
		self:stop_("002 before 001")
		return
	end
	if not yourhost then
		self:stop_("002 with no yourhost line")
		return
	end
	self.welcome_.yourhost = yourhost
end

function client_i:handle_003_(created) -- * RPL_CREATED
	if not self.welcome_ then
		self:stop_("003 before 001")
		return
	end
	if not created then
		self:stop_("003 with no created line")
		return
	end
	self.welcome_.created = created
end

function client_i:handle_004_(server_name, server_version, user_modes, channel_modes) -- * RPL_MYINFO
	if not self.welcome_ then
		self:stop_("004 before 001")
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
end

function client_i:handle_005_(client, ...) -- * RPL_ISUPPORT, hopefully
	if not self.receiving_isupport_ and self.isupport_tokens_ then
		-- * TODO: handle these, stop when casemapping randomly changes, etc.
		self:warn_("005 when ISUPPORT tokens already received")
		return
	end
	if not self:check_client_self_("005", client) then
		return
	end
	self.receiving_isupport_ = true
	local tokens = { ... }
	if #tokens == 0 then
		self:stop_("005 with no tokens specified")
		return
	end
	if #tokens == 1 then
		self:warn_("005 matching format of legacy RPL_BOUNCE")
		self.compat_flags_.no_isupport = true
		self:stop_("bounced (005): " .. tokens[1])
		return
	end
	if not self.isupport_tokens_ then
		self.isupport_tokens_ = {}
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
	self:stop_("bounced (010): " .. table.concat({ ... }, " "))
end

function client_i:handle_250_(client, ...) -- * RPL_STATSDLINE, RPL_STATSCONN
	if not self:check_client_self_("250", client) then
		return
	end
	self:call_hook_("250", ...)
end

function client_i:handle_251_(client, ...) -- * RPL_LUSERCLIENT
	if not self:check_client_self_("251", client) then
		return
	end
	self.receiving_lusers_ = {}
	self.receiving_lusers_.client = table.concat({ ... }, " ")
end

function client_i:handle_252_(client, ...) -- * RPL_LUSEROP
	if not self.receiving_lusers_ then
		self:stop_("252 while not receiving lusers")
		return
	end
	if not self:check_client_self_("252", client) then
		return
	end
	self.receiving_lusers_.op = table.concat({ ... }, " ")
end

function client_i:handle_253_(client, ...) -- * RPL_LUSERUNKNOWN
	if not self.receiving_lusers_ then
		self:stop_("253 while not receiving lusers")
		return
	end
	if not self:check_client_self_("253", client) then
		return
	end
	self.receiving_lusers_.unknown = table.concat({ ... }, " ")
end

function client_i:handle_254_(client, ...) -- * RPL_LUSERCHANNELS
	if not self.receiving_lusers_ then
		self:stop_("254 while not receiving lusers")
		return
	end
	if not self:check_client_self_("254", client) then
		return
	end
	self.receiving_lusers_.channels = table.concat({ ... }, " ")
end

function client_i:handle_255_(client, ...) -- * RPL_LUSERME
	if not self:check_client_self_("255", client) then
		return
	end
	self.receiving_lusers_.me = table.concat({ ... }, " ")
	self.lusers_ = self.receiving_lusers_
	self.receiving_lusers_ = nil
	self:call_hook_("lusers", self.lusers_)
end

function client_i:handle_263_(command) -- * RPL_TRYAGAIN
	if command == "nick" then
		if self.setting_nick_ then
			self.set_nick_error_ = 263
			self.setting_nick_:signal()
			self.setting_nick_ = nil
		else
			self:warn_("263 to nick while not setting nick")
		end
	elseif command == "away" then
		if self.setting_away_ then
			self.set_away_error_ = 263
			self.setting_away_:signal()
			self.setting_away_ = nil
		else
			self:warn_("263 to away while not setting away")
		end
	else
		self:warn_("263 to " .. command)
	end
end

function client_i:handle_265_(client, ...) -- * RPL_LOCALUSERS
	if not self:check_client_self_("265", client) then
		return
	end
	self.lusers_.loc = table.concat({ ... }, " ")
end

function client_i:handle_266_(client, ...) -- * RPL_GLOBALUSERS
	if not self:check_client_self_("266", client) then
		return
	end
	self.lusers_.glob = table.concat({ ... }, " ")
	self:call_hook_("luserslocglob", self.lusers_)
end

function client_i:handle_301_(nick) -- * RPL_AWAY
	if not nick then
		self:stop_("301 with no nick specified")
		return
	end
	nick = self:lower(nick)
	if self.users_in_channels_[nick] then
		-- * TODO: update away status
	end
end

function client_i:handle_305_() -- * RPL_UNAWAY
	if self.away_ then
		self.away_ = nil
		self:call_hook_("unaway")
	else
		self:warn_("305 while not away")
	end
	if self.setting_away_ then
		self.setting_away_:signal()
		self.setting_away_ = nil
	end
end

function client_i:handle_306_() -- * RPL_NOWAWAY
	if self.away_ then
		self:warn_("306 while away")
	else
		self.away_ = self.away_message_sent_
		self.away_message_sent_ = nil
		self:call_hook_("away", self.away_)
	end
	if self.setting_away_ then
		self.setting_away_:signal()
		self.setting_away_ = nil
	end
end

function client_i:handle_331_(client, channel, topic) -- * RPL_NOTOPIC
	if not self:check_client_self_("331", client) then
		return
	end
	if not channel then
		self:stop_("331 with no channel specified")
		return
	end
	channel = self:lower(channel)
	if not self.channels_[channel] then
		self:warn_("331 for channel " .. channel .. " while not joined")
		return
	end
	self.channels_[channel].topic_ = nil
	self:call_hook_("topic", self.channels_[channel])
end

function client_i:handle_332_(client, channel, topic) -- * RPL_TOPIC
	if not self:check_client_self_("332", client) then
		return
	end
	if not channel then
		self:stop_("332 with no channel specified")
		return
	end
	channel = self:lower(channel)
	if not topic then
		self:stop_("332 with no topic specified")
		return
	end
	if not self.channels_[channel] then
		self:warn_("332 for channel " .. channel .. " while not joined")
		return
	end
	self.channels_[channel].topic_ = topic
	self:call_hook_("topic", self.channels_[channel])
end

function client_i:handle_333_(client, channel, nick, setat) -- * RPL_TOPICWHOTIME
	if not self:check_client_self_("333", client) then
		return
	end
	if not channel then
		self:stop_("333 with no channel specified")
		return
	end
	channel = self:lower(channel)
	if not nick then
		self:stop_("333 with no nick specified")
		return
	end
	if not setat then
		self:stop_("333 with no setat specified")
		return
	end
	if not self.channels_[channel] then
		self:warn_("333 for channel " .. channel .. " while not joined")
		return
	end
	self.channels_[channel].topic_by_ = nick
	self.channels_[channel].topic_at_ = setat
	self:call_hook_("topicwhotime", self.channels_[channel])
end

do
	local symbol_lookup = {
		["="] = "public",
		["@"] = "secret",
		["*"] = "private",
	}

	function client_i:handle_353_(client, symbol, channel, prefixes_and_nicks) -- * RPL_NAMREPLY
		if not self:check_client_self_("353", client) then
			return
		end
		if not symbol then
			self:stop_("353 with no symbol specified")
			return
		end
		if not channel then
			self:stop_("353 with no channel specified")
			return
		end
		channel = self:lower(channel)
		if not prefixes_and_nicks then
			self:stop_("353 with no nicks specified")
			return
		end
		if not self.channels_[channel] then
			self:warn_("353 for channel " .. channel .. " while not joined")
			return
		end
		self.channels_[channel].status_ = symbol_lookup[symbol] or "unknown"
		for prefix_and_nick in prefixes_and_nicks:gmatch("[^ ]+") do
			local raw_nick = prefix_and_nick
			local prefix_letter = raw_nick:sub(1, 1)
			local prefix_mode = self.prefix_letter_to_mode_[prefix_letter]
			if prefix_mode then
				raw_nick = raw_nick:sub(2)
			end
			if ok_nick(raw_nick) then
				local nick = self:lower(raw_nick)
				self:add_user_to_channel_(channel, nick, raw_nick)
				self.channels_[channel].highest_modes_[nick] = prefix_mode
			else
				self:warn_("invalid nick-prefix pair in 353: " .. prefix_and_nick)
			end
		end
	end
end

function client_i:handle_366_(client, channel) -- * RPL_ENDOFNAMES
	if not self:check_client_self_("366", client) then
		return
	end
	if not channel then
		self:stop_("366 with no channel specified")
		return
	end
	channel = self:lower(channel)
	if not self.channels_[channel] then
		self:warn_("366 for channel " .. channel .. " while not joined")
		return
	end
	self:call_hook_("names", self.channels_[channel])
end

function client_i:handle_372_(motd_line) -- * RPL_MOTD
	if not self.receiving_motd_ then
		self:stop_("372 while not receiving motd")
		return
	end
	if not motd_line then
		self:stop_("372 with no motd line")
		return
	end
	table.insert(self.motd_, motd_line)
end

function client_i:handle_375_() -- * RPL_MOTDSTART
	if self.receiving_motd_ then
		self:stop_("375 while already receiving motd")
		return
	end
	self.receiving_motd_ = true
	self.motd_ = {}
end

function client_i:handle_376_() -- * RPL_ENDOFMOTD
	if not self.receiving_motd_ then
		self:stop_("376 while not receiving motd")
		return
	end
	self.receiving_motd_ = nil
	self:call_hook_("motd", self.motd_)
end

function client_i:handle_422_() -- * ERR_NOMOTD
	self.motd_ = false
	self:call_hook_("motd", self.motd_)
end

function client_i:handle_432_(command) -- * ERR_ERRONEUSNICKNAME
	if self.setting_nick_ then
		self.set_nick_error_ = 432
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	else
		self:warn_("432 while not setting nick")
	end
end

function client_i:handle_433_(command) -- * ERR_NICKNAMEINUSE
	if self.setting_nick_ then
		self.set_nick_error_ = 433
		self.setting_nick_:signal()
		self.setting_nick_ = nil
	else
		self:warn_("433 while not setting nick")
	end
end

function client_i:handle_436_(command) -- * ERR_NICKCOLLISION
	self:stop_("nick collision")
end

function client_i:handle_437_(nick_or_channel) -- * ERR_UNAVAILRESOURCE
	if ok_nick(nick_or_channel) then
		local nick = self:lower(nick_or_channel)
		-- * Assume it's a nick.
		if self.setting_nick_ then
			self.set_nick_error_ = 437
			self.setting_nick_:signal()
			self.setting_nick_ = nil
		else
			self:warn_("437 while not setting nick")
		end
	else
		local channel = self:lower(nick_or_channel)
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
		self:warn_("484 while not setting nick")
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
	for raw_name in channels:gmatch("[^,]+") do
		local name = self:lower(raw_name)
		if self.channels_[name] then
			self:warn_("channel " .. name .. " in join list while already joined")
		else
			if self:prefix_is_self_() then
				self.channels_[name] = setmetatable({
					client_ = self,
					name_ = name,
					raw_name_ = raw_name,
					highest_modes_ = {},
					users_ = {},
				}, channel_m)
				self:call_hook_("self_join", self.channels_[name])
			else
				self:add_user_to_channel_(name, self.last_prefix_.nick, self.last_prefix_.raw_nick)
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

function client_i:handle_notice_(target, message)
	if not self.last_prefix_.nick then
		self:stop_("notice with no nickname specified in prefix")
		return
	end
	if not target then
		self:stop_("notice with no target specified")
		return
	end
	if not message then
		self:stop_("notice with no message specified")
		return
	end
	self:call_hook_("notice", self.last_prefix_.nick, target, message)
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
	for raw_name in channels:gmatch("[^,]+") do
		local name = self:lower(raw_name)
		if not self.channels_[name] then
			self:warn_("channel " .. name .. " in part list while not joined")
		else
			if self:prefix_is_self_() then
				for nick in pairs(self.channels_[name].users_) do
					self:remove_user_from_channel_(name, nick)
				end
				self.channels_[name] = nil
				self:call_hook_("self_part", self.channels_[name])
			else
				self:remove_user_from_channel_(name, self.last_prefix_.nick)
			end
		end
	end
end

function client_i:handle_privmsg_(target, message)
	if not self.last_prefix_.nick then
		self:stop_("privmsg with no nickname specified in prefix")
		return
	end
	if not target then
		self:stop_("privmsg with no target specified")
		return
	end
	if not message then
		self:stop_("privmsg with no message specified")
		return
	end
	self:call_hook_("privmsg", self.last_prefix_.nick, target, message)
end

function client_i:handle_ping_(server, server2)
	if not server then
		self:stop_("ping with no server specified")
		return
	end
	if server2 then
		self:send_("pong", { server }, server2)
	else
		self:send_("pong", {}, server)
	end
end

function client_i:pre_handler_(command) -- * Used for edge-triggering.
	if self.isupport_tokens_ and command ~= "005" then
		self.receiving_isupport_ = nil
		if not next(self.isupport_tokens_) then
			-- * TODO: handle this somehow
			self:warn_("server sent no ISUPPORT tokens")
			self.compat_flags_.no_isupport = true
		end
		self:process_isupport_()
	end
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
			elseif self.quitting_ then
				self:stop_()
			else
				self:stop_("read failed: " .. tostring(err or "eof"))
			end
		end
	end
end

function client_i:remove_user_from_channel_(channel, nick)
	self.channels_[channel].users_[nick] = nil
	self.users_in_channels_[nick].channels_[channel] = nil
	if not next(self.users_in_channels_[nick].channels_) then
		self:call_hook_("user_disappear", self.users_in_channels_[nick])
		self.users_in_channels_[nick] = nil
	end
end

function client_i:add_user_to_channel_(channel, nick, raw_nick)
	if not self.users_in_channels_[nick] then
		self.users_in_channels_[nick] = setmetatable({
			name_ = nick,
			raw_name_ = raw_nick,
			channels_ = {},
		}, user_m)
		self:call_hook_("user_appear", self.users_in_channels_[nick])
	end
	self.channels_[channel].users_[nick] = self.users_in_channels_[nick]
	self.users_in_channels_[nick].channels_[channel] = true
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
			self:warn_(("unhandled command: %s: %s %s"):format(prefix or "?", command, table.concat(quoted_params, " ")))
		end
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
		self.last_prefix_.raw_nick = nick or false
		self.last_prefix_.user = user or false
		self.last_prefix_.host = host or false
	else
		self.last_prefix_.nick = false
		self.last_prefix_.raw_nick = false
		self.last_prefix_.user = false
		self.last_prefix_.host = false
	end
end

function client_i:process_isupport_casemapping_(casemapping)
	if not casemapping then
		self:warn_("no CASEMAPPING ISUPPORT token received, not changing currently effective casemapping " .. self.casemapping_)
		return true
	end
	if not casemappings[casemapping] then
		self:stop_("unknown casemapping: " .. casemapping)
		return
	end
	local old_nick = self.nick_
	self.casemapping_ = casemapping
	if self:lower(self.raw_nick_) ~= old_nick then
		self:update_nick_(self.raw_nick_)
	end
	return true
end

function client_i:export_prefix_mapping_()
	local modes = {}
	local letters = {}
	for mode, letter in pairs(self.prefix_mode_to_letter_) do
		table.insert(modes, mode)
		table.insert(letters, letter)
	end
	return "(" .. table.concat(modes) .. ")" .. table.concat(letters)
end

function client_i:process_isupport_prefix_(prefixes)
	if not prefixes then
		self:warn_("no PREFIX ISUPPORT token received, not changing currently effective prefix mapping " .. self:export_prefix_mapping_())
		return true
	end
	if prefixes == "" then
		prefixes = "()"
	end
	local modes, letters = prefixes:match("^%(([^%)]*)%)(.*)$")
	if #modes ~= #letters then
		self:stop_("invalid prefix mapping: " .. casemapping)
		return false
	end
	local ambiguous = false
	do
		local used = {}
		for mode in modes:gmatch(".") do
			if used[mode] then
				ambiguous = true
			end
			used[mode] = true
		end
	end
	do
		local used = {}
		for letter in letters:gmatch(".") do
			if used[letter] then
				ambiguous = true
			end
			used[letter] = true
		end
	end
	if ambiguous then
		self:stop_("ambiguous prefix mapping: " .. casemapping)
		return false
	end
	self.prefix_mode_to_letter_ = {}
	self.prefix_letter_to_mode_ = {}
	for ix = 1, #modes do
		self.prefix_mode_to_letter_[modes:sub(ix, ix)] = letters:sub(ix, ix)
		self.prefix_letter_to_mode_[letters:sub(ix, ix)] = modes:sub(ix, ix)
	end
	return true
end

function client_i:process_isupport_()
	if not self:process_isupport_casemapping_(self.isupport_tokens_.CASEMAPPING) then
		return
	end
	if not self:process_isupport_prefix_(self.isupport_tokens_.PREFIX) then
		return
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
	local target = assert_param(ok_nick_or_channel, target_in, "target")
	local message = assert_param(ok_string, message_in, "message")
	self:send_("privmsg", { target }, message)
end

function client_i:notice(target_in, message_in)
	self:assert_chat_phase_()
	local target = assert_param(ok_nick_or_channel, target_in, "target")
	local message = assert_param(ok_string, message_in, "message")
	self:send_("notice", { target }, message)
end

function client_i:quit(message_in)
	local message = assert_param_default(ok_string, message_in, "message") or self.default_quit_message_
	self.quitting_ = true
	self:send_("quit", {}, message)
end

function client_i:stop_(stop_reason)
	if stop_reason then
		if not self.all_stop_reasons_ then
			self.all_stop_reasons_ = {}
		end
		table.insert(self.all_stop_reasons_, stop_reason)
	end
	if self.status_ ~= "dead" then
		self:call_hook_("stop", stop_reason)
		self.status_ = "dead"
		self.stop_reason_ = stop_reason
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
			self.queue_:wrap(hook, self, ...)
		end
	end
end

function client_i:check_client_(command, client)
	if not client then
		self:stop_(command .. " with no client specified")
		return false
	end
	self.last_client_ = client
	return true
end

function client_i:check_client_self_(command, client)
	if not self:check_client_(command, client) then
		return false
	end
	if self:lower(client) ~= self.nick_ then
		self:stop_(command .. " addressed to the wrong client")
		return false
	end
	return true
end

function client_i:disconnect_()
	self.client_socket_:close()
end

function client_i:register_()
	self:send_("pass", {}, self.pass_)
	self:send_("nick", { self.raw_nick_ })
	self:send_("user", { self.user_, "0", "*" }, self.real_)
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
		user_ = assert_param(ok_user, params.user, "user"),
		raw_nick_ = assert_param(ok_nick, params.nick, "nick"),
		pass_ = assert_param(ok_nonempty_string, params.pass, "pass"),
		real_ = assert_param(ok_nonempty_string, params.real, "real"),
		status_ = "ready",
		use_tls_ = params.tls and true or false,
		tls_ctx_ = params.tls and (assert_param_default(ok_openssl_context, params.tls_ctx, "tls_ctx") or make_tls_context()),
		queue_ = assert_param_default(ok_cqueues_controller, params.queue, "queue") or cqueues.new(),
		message_size_limit_ = assert_param_default(ok_integer, params.message_size_limit, "message_size_limit") or 512,
		default_quit_message_ = "quit",
		default_away_message_ = "away",
		hooks_ = {},
		compat_flags_ = {},
		last_prefix_ = {},
		channels_ = {},
		users_in_channels_ = {},
		casemapping_ = "rfc1459-strict",
		prefix_mode_to_letter_ = { ["o"] = "@", ["v"] = "+" },
		prefix_letter_to_mode_ = { ["@"] = "o", ["+"] = "v" },
	}, client_m)
	client.nick_ = client:lower(client.raw_nick_)
	return client
end

return {
	client = make_client
}
