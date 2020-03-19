local cqueues = require("cqueues")
local socket = require("cqueues.socket")
local condition = require("cqueues.condition")
local ssl = require("openssl.ssl")
local ssl_ctx = require("openssl.ssl.context")
local ssl_pkey = require("openssl.pkey")

local unpack = rawget(_G, "unpack") or table.unpack
local bit = rawget(_G, "bit") or rawget(_G, "bit32")

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

function client_i:get_death_reason()
	return self.death_reason_
end

function client_i:get_nick()
	return self.nick_
end

function client_i:get_status()
	return self.status_
end

local function parse_prefix(prefix)
	local nick, user, host = prefix:match("^([^!]*)!([^@]*)@([^@]*)$")
	return nick, user, host -- * Just so I know what I'm returning.
end

local function parse_line(line_without_crlf)
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

function client_i:handle_372_(motd_line)
	if not self.receiving_motd_ then
		self:warn_incoming_("372 while not receiving motd")
		return
	end
	if not motd_line then
		self:warn_incoming_("372 with no motd line specified")
		return
	end
	table.insert(self.motd_, motd_line)
end

function client_i:handle_375_()
	if self.receiving_motd_ then
		self:warn_incoming_("375 while already receiving motd")
		return
	end
	self.receiving_motd_ = true
	self.motd_ = {}
end

function client_i:handle_376_()
	if not self.receiving_motd_ then
		self:warn_incoming_("376 while not receiving motd")
		return
	end
	self.receiving_motd_ = false
end

function client_i:handle_nick_(new)
	local old = parse_prefix(self.last_prefix_)
	if not old then
		self:warn_incoming_("nick with no nickname specified in prefix")
		return
	end
	if not new then
		self:warn_incoming_("nick with no new nickname specified")
		return
	end
	if old == self.nick_ then
		self.nick_ = new
	end
end

function client_i:handle_ping_(server, server2)
	if not server then
		self:warn_incoming_("ping with no server specified")
		return
	end
	self:send_("pong", { server, server2 })
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
				local command, params, prefix = parse_line(line_without_crlf)
				if command then
					self.last_prefix_ = prefix or false
					local handler = self["handle_" .. command .. "_"]
					if handler then
						handler(self, unpack(params))
					else
						self:warn_incoming_(("unhandled command: %s: %s %s"):format(prefix or "?", command, table.concat(params, " ")))
					end
				end
			else
				self:stop_("read failed: " .. tostring(err))
			end
		end
	end
end

function client_i:privmsg(target_in, message_in)
	local target = assert_param(ok_nonempty_string, target_in, "target")
	local message = assert_param(ok_string, message_in, "message")
	self:send_("privmsg", { target }, message)
end

function client_i:quit(message_in)
	local message = assert_param_default(ok_string, message_in, "message") or self.default_quit_message_
	self:send_("quit", {}, message)
end

function client_i:stop_(death_reason)
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
	self.queue_:wrap(function()
		self.connecting_ = false
		self:send_("pass", {}, self.pass_)
		self:send_("nick", { self.nick_ })
		self:send_("user", { self.user_, "0", "*" }, self.real_)
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

local function make_client(params)
	local client = setmetatable({
		host_ = assert_param(ok_nonempty_string, params.host, "host"),
		port_ = assert_param(ok_integer, params.port, "port"),
		user_ = assert_param(ok_nonempty_string, params.user, "user"),
		nick_ = assert_param(ok_nonempty_string, params.nick, "nick"),
		pass_ = assert_param(ok_nonempty_string, params.pass, "pass"),
		real_ = assert_param(ok_nonempty_string, params.real, "real"),
		status_ = "ready",
		use_tls_ = params.tls and true or false,
		tls_ctx_ = params.tls and (assert_param_default(ok_openssl_context, params.tls_ctx, "tls_ctx") or make_tls_context()),
		queue_ = assert_param_default(ok_cqueues_controller, params.queue, "queue") or cqueues.new(),
		message_size_limit_ = assert_param_default(ok_integer, params.message_size_limit, "message_size_limit") or 512,
		last_prefix_ = false,
		receiving_motd_ = false,
		death_reason_ = false,
		connecting_ = false,
		motd_ = {},
		hooks_ = {},
		default_quit_message_ = "quit",
	}, client_m)
	return client
end

return {
	client = make_client
}
