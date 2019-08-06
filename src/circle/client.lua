local cqueues = require("cqueues")
local socket = require("cqueues.socket")
local ssl = require("openssl.ssl")
local ssl_ctx = require("openssl.ssl.context")
local ssl_pkey = require("openssl.pkey")
local format = require("circle.format")

local unpack = unpack or table.unpack

local client_i = {}
local client_m = { __index = client_i }

function client_i:handle_001_(message) -- RPL_WELCOME
	self.registered_ = true
	self.welcome_.message = message
end

function client_i:handle_002_(yourhost) -- RPL_YOURHOST
	self.welcome_.yourhost = yourhost
end

function client_i:handle_003_(created) -- RPL_CREATED
	self.welcome_.created = created
end

function client_i:handle_004_(server_name, version, user_modes, channel_modes) -- RPL_MYINFO
	self.welcome_.server_name = server_name
	self.welcome_.version = version
	self.welcome_.user_modes = user_modes
	self.welcome_.channel_modes = channel_modes
	-- * TODO: signal WELCOME completion
end

function client_i:handle_005_() -- RPL_BOUNCE
	-- * TODO: advanced IRC stuff?
end

-- * TODO: 200 -- RPL_TRACELINK
-- * TODO: 201 -- RPL_TRACECONNECTING
-- * TODO: 202 -- RPL_TRACEHANDSHAKE
-- * TODO: 203 -- RPL_TRACEUNKNOWN
-- * TODO: 204 -- RPL_TRACEOPERATOR
-- * TODO: 205 -- RPL_TRACEUSER
-- * TODO: 206 -- RPL_TRACESERVER
-- * TODO: 207 -- RPL_TRACESERVICE
-- * TODO: 208 -- RPL_TRACENEWTYPE
-- * TODO: 209 -- RPL_TRACECLASS
-- * TODO: 210 -- RPL_TRACERECONNECT
-- * TODO: 211 -- RPL_STATSLINKINFO
-- * TODO: 212 -- RPL_STATSCOMMANDS
-- * TODO: 213 -- RPL_STATSCLINE
-- * TODO: 214 -- RPL_STATSNLINE
-- * TODO: 215 -- RPL_STATSILINE
-- * TODO: 216 -- RPL_STATSKLINE
-- * TODO: 217 -- RPL_STATSQLINE
-- * TODO: 218 -- RPL_STATSYLINE
-- * TODO: 219 -- RPL_ENDOFSTATS
-- * TODO: 221 -- RPL_UMODEIS
-- * TODO: 231 -- RPL_SERVICEINFO
-- * TODO: 232 -- RPL_ENDOFSERVICES
-- * TODO: 233 -- RPL_SERVICE
-- * TODO: 234 -- RPL_SERVLIST
-- * TODO: 235 -- RPL_SERVLISTEND
-- * TODO: 240 -- RPL_STATSVLINE
-- * TODO: 241 -- RPL_STATSLLINE
-- * TODO: 242 -- RPL_STATSUPTIME
-- * TODO: 243 -- RPL_STATSOLINE
-- * TODO: 244 -- RPL_STATSHLINE
-- * TODO: 245 -- RPL_STATSSLINE
-- * TODO: 246 -- RPL_STATSPING
-- * TODO: 247 -- RPL_STATSBLINE

function client_i:handle_250_(dline) -- RPL_STATSDLINE
	self.misc_.stats_dline = dline
end

function client_i:handle_251_(client) -- RPL_LUSERCLIENT
	self.luser_ = {}
	self.luser_.client = client
end

function client_i:handle_252_(op) -- RPL_LUSEROP
	self.luser_.op = op
end

function client_i:handle_253_(unknown) -- RPL_LUSERUNKNOWN
	self.luser_.unknown = unknown
end

function client_i:handle_254_(channels) -- RPL_LUSERCHANNELS
	self.luser_.channels = channels
end

function client_i:handle_255_(me) -- RPL_LUSERME
	self.luser_.me = me
	-- * TODO: signal LUSER completion
end

function client_i:handle_265_(local_current, local_max) -- ??? TODO: figure out
	-- * advanced IRC stuff?
end

function client_i:handle_266_(global_current, global_max) -- ??? TODO: figure out
	-- * advanced IRC stuff?
end

-- * TODO: 256 -- RPL_ADMINME
-- * TODO: 257 -- RPL_ADMINLOC1
-- * TODO: 258 -- RPL_ADMINLOC2
-- * TODO: 259 -- RPL_ADMINEMAIL
-- * TODO: 261 -- RPL_TRACELOG
-- * TODO: 262 -- RPL_TRACEEND
-- * TODO: 263 -- RPL_TRYAGAIN
-- * TODO: 300 -- RPL_NONE
-- * TODO: 301 -- RPL_AWAY
-- * TODO: 302 -- RPL_USERHOST
-- * TODO: 303 -- RPL_ISON

function client_i:handle_305_() -- RPL_UNAWAY
	self.away_ = false
	-- * TODO: signal AWAY completion
end

function client_i:handle_306_() -- RPL_NOWAWAY
	self.away_ = true
	-- * TODO: signal AWAY completion
end

-- * TODO: 311 -- RPL_WHOISUSER
-- * TODO: 312 -- RPL_WHOISSERVER
-- * TODO: 313 -- RPL_WHOISOPERATOR
-- * TODO: 314 -- RPL_WHOWASUSER
-- * TODO: 315 -- RPL_ENDOFWHO
-- * TODO: 316 -- RPL_WHOISCHANOP
-- * TODO: 317 -- RPL_WHOISIDLE
-- * TODO: 318 -- RPL_ENDOFWHOIS
-- * TODO: 319 -- RPL_WHOISCHANNELS
-- * TODO: 321 -- RPL_LISTSTART
-- * TODO: 322 -- RPL_LIST
-- * TODO: 323 -- RPL_LISTEND
-- * TODO: 324 -- RPL_CHANNELMODEIS
-- * TODO: 325 -- RPL_UNIQOPIS

function client_i:handle_331_(channel) -- RPL_NOTOPIC
	if not self.channels_[channel] then
		-- * TODO: warn
		return
	end
	self.channels_[channel].topic = false
	-- * TODO: signal TOPIC completion
end

function client_i:handle_332_(channel, topic) -- RPL_TOPIC
	if not self.channels_[channel] then
		-- * TODO: warn
		return
	end
	self.channels_[channel].topic = topic
	-- * TODO: signal TOPIC completion
end

function client_i:handle_333_(channel, who, time) -- RPL_TOPICWHOTIME
	-- * TODO: advanced IRC stuff?
end

-- * TODO: 341 -- RPL_INVITING
-- * TODO: 342 -- RPL_SUMMONING
-- * TODO: 346 -- RPL_INVITELIST
-- * TODO: 347 -- RPL_ENDOFINVITELIST
-- * TODO: 348 -- RPL_EXCEPTLIST
-- * TODO: 349 -- RPL_ENDOFEXCEPTLIST
-- * TODO: 351 -- RPL_VERSION
-- * TODO: 352 -- RPL_WHOREPLY
-- * TODO: 353 -- RPL_NAMREPLY
-- * TODO: 361 -- RPL_KILLDONE
-- * TODO: 362 -- RPL_CLOSING
-- * TODO: 363 -- RPL_CLOSEEND
-- * TODO: 364 -- RPL_LINKS
-- * TODO: 365 -- RPL_ENDOFLINKS
-- * TODO: 366 -- RPL_ENDOFNAMES
-- * TODO: 367 -- RPL_BANLIST
-- * TODO: 368 -- RPL_ENDOFBANLIST
-- * TODO: 369 -- RPL_ENDOFWHOWAS
-- * TODO: 371 -- RPL_INFO

function client_i:handle_372_(text) -- RPL_MOTD
	table.insert(self.motd_, text)
end

-- * TODO: 373 -- RPL_INFOSTART
-- * TODO: 374 -- RPL_ENDOFINFO

function client_i:handle_375_() -- RPL_MOTDSTART
	self.motd_ = {}
end

function client_i:handle_376_(text) -- RPL_ENDOFMOTD
	-- * TODO: signal MOTD completion
end

-- * TODO: 381 -- RPL_YOUREOPER
-- * TODO: 382 -- RPL_REHASHING
-- * TODO: 383 -- RPL_YOURESERVICE
-- * TODO: 384 -- RPL_MYPORTIS
-- * TODO: 391 -- RPL_TIME
-- * TODO: 392 -- RPL_USERSSTART
-- * TODO: 393 -- RPL_USERS
-- * TODO: 394 -- RPL_ENDOFUSERS
-- * TODO: 395 -- RPL_NOUSERS
-- * TODO: 401 -- ERR_NOSUCHNICK
-- * TODO: 402 -- ERR_NOSUCHSERVER
-- * TODO: 403 -- ERR_NOSUCHCHANNEL
-- * TODO: 404 -- ERR_CANNOTSENDTOCHAN
-- * TODO: 405 -- ERR_TOOMANYCHANNELS
-- * TODO: 406 -- ERR_WASNOSUCHNICK
-- * TODO: 407 -- ERR_TOOMANYTARGETS
-- * TODO: 408 -- ERR_NOSUCHSERVICE
-- * TODO: 409 -- ERR_NOORIGIN
-- * TODO: 411 -- ERR_NORECIPIENT
-- * TODO: 412 -- ERR_NOTEXTTOSEND
-- * TODO: 413 -- ERR_NOTOPLEVEL
-- * TODO: 414 -- ERR_WILDTOPLEVEL
-- * TODO: 415 -- ERR_BADMASK
-- * TODO: 421 -- ERR_UNKNOWNCOMMAND
-- * TODO: 422 -- ERR_NOMOTD
-- * TODO: 423 -- ERR_NOADMININFO
-- * TODO: 424 -- ERR_FILEERROR
-- * TODO: 431 -- ERR_NONICKNAMEGIVEN
-- * TODO: 432 -- ERR_ERRONEUSNICKNAME
-- * TODO: 433 -- ERR_NICKNAMEINUSE
-- * TODO: 436 -- ERR_NICKCOLLISION
-- * TODO: 437 -- ERR_UNAVAILRESOURCE
-- * TODO: 441 -- ERR_USERNOTINCHANNEL
-- * TODO: 442 -- ERR_NOTONCHANNEL
-- * TODO: 443 -- ERR_USERONCHANNEL
-- * TODO: 444 -- ERR_NOLOGIN
-- * TODO: 445 -- ERR_SUMMONDISABLED
-- * TODO: 446 -- ERR_USERSDISABLED
-- * TODO: 451 -- ERR_NOTREGISTERED
-- * TODO: 461 -- ERR_NEEDMOREPARAMS
-- * TODO: 462 -- ERR_ALREADYREGISTRED
-- * TODO: 463 -- ERR_NOPERMFORHOST
-- * TODO: 464 -- ERR_PASSWDMISMATCH
-- * TODO: 465 -- ERR_YOUREBANNEDCREEP
-- * TODO: 466 -- ERR_YOUWILLBEBANNED
-- * TODO: 467 -- ERR_KEYSET
-- * TODO: 471 -- ERR_CHANNELISFULL
-- * TODO: 472 -- ERR_UNKNOWNMODE
-- * TODO: 473 -- ERR_INVITEONLYCHAN
-- * TODO: 474 -- ERR_BANNEDFROMCHAN
-- * TODO: 475 -- ERR_BADCHANNELKEY
-- * TODO: 476 -- ERR_BADCHANMASK
-- * TODO: 477 -- ERR_NOCHANMODES
-- * TODO: 478 -- ERR_BANLISTFULL
-- * TODO: 481 -- ERR_NOPRIVILEGES
-- * TODO: 482 -- ERR_CHANOPRIVSNEEDED
-- * TODO: 483 -- ERR_CANTKILLSERVER
-- * TODO: 484 -- ERR_RESTRICTED
-- * TODO: 485 -- ERR_UNIQOPPRIVSNEEDED
-- * TODO: 491 -- ERR_NOOPERHOST
-- * TODO: 492 -- ERR_NOSERVICEHOST
-- * TODO: 501 -- ERR_UMODEUNKNOWNFLAG
-- * TODO: 502 -- ERR_USERSDONTMATCH

function client_i:handle_join_(keys)
	for channel in self.last_target_:gmatch("[^,]+") do
		self.channels_[channel] = {
			topic = false
		}
	end
	-- * TODO: signal JOIN completion for each channel
end

function client_i:handle_mode_(modes)
	-- * TODO: record modes
end

function client_i:handle_ping_(sender, origin)
	self:send_("pong", { sender, origin })
end

function client_i:handle_privmsg_(message)
	if self.last_target_ == "##hellomouse" and message:find("^&&") then
		self:send_("privmsg", { "##hellomouse" }, "bananas")
	end
end

function client_i:connect_()
	self.client_socket_ = assert(socket.connect({
		host = self.host_,
		port = self.port_,
		sendname = self.tls_,
	}))
	if self.tls_ then
		self.ssl_ = ssl.new(self.ctx_)
		assert(self.client_socket_:starttls(self.ssl_))
	end
end

function client_i:send_(command, middles, trailing, prefix)
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
	self.client_socket_:write(data)
end

function client_i:register_()
	self:send_("pass", {}, self.pass_)
	self:send_("nick", { self.nick_ })
	self:send_("user", { self.user_, "0", "*" }, self.real_)
end

function client_i:handle_commands_()
	for line_without_crlf in self.client_socket_:lines() do
		print("\27[34m" .. line_without_crlf .. "\27[0m")
		local command, params, prefix = format.parse_line(line_without_crlf)
		self.last_prefix_ = prefix
		self.last_target_ = params[1]
		if not command then
			error("failed to parse line: " .. line_without_crlf)
		end
		local command_handler = self[("handle_%s_"):format(command:lower())]
		if command_handler then
			command_handler(self, unpack(params, 2))
		else
			-- * TODO: warn
		end
		if not self.running_ then
			break
		end
	end
end

function client_i:shutdown()
	self.send_("quit", {})
	self.running_ = false
end

function client_i:disconnect_()
	self.client_socket_:close()
end

function client_i:run_()
	self:connect_()
	self:register_()
	self:handle_commands_()
	self:disconnect_()
end

function client_i:loop()
	assert(self.queue_:loop())
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
	ctx:setOptions(
		ssl_ctx.OP_NO_COMPRESSION +
		ssl_ctx.OP_SINGLE_ECDH_USE +
		ssl_ctx.OP_NO_SSLv2 +
		ssl_ctx.OP_NO_SSLv3
	)
	ctx:setEphemeralKey(ssl_pkey.new({
		type = "EC",
		curve = "prime256v1"
	}))
	ctx:getStore():addDefaults()
	ctx:setVerify(ssl_ctx.VERIFY_PEER)
	return ctx
end

local function make_client(params)
	local client = setmetatable({
		host_ = params.host or error("missing .host", 2),
		port_ = params.port or error("missing .port", 2),
		user_ = params.user or error("missing .user", 2),
		nick_ = params.nick or error("missing .nick", 2),
		pass_ = params.pass or error("missing .pass", 2),
		real_ = params.real or error("missing .real", 2),
		message_size_limit_ = params.message_size_limit or 512,
		queue_ = params.queue or cqueues.new(),
		tls_ = params.tls and true or false,
		ctx_ = params.tls and (params.ctx or make_tls_context()),
		running_ = true,
		registered_ = false,
		welcome_ = {},
		luser_ = {},
		motd_ = {},
		misc_ = {},
		channels_ = {},
		away_ = false,
	}, client_m)
	if not format.valid_user(client.user_) then
		error("invalid .user", 2)
	end
	if not format.valid_nick(client.nick_) then
		error("invalid .nick", 2)
	end
	if not format.valid_pass(client.pass_) then
		error("invalid .pass", 2)
	end
	if not format.valid_real(client.real_) then
		error("invalid .real", 2)
	end
	client.queue_:wrap(function()
		client:run_()
	end)
	return client
end

return {
	client = make_client
}
