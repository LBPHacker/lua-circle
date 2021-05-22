local cqueues = require("cqueues")
local ssl_ctx = require("openssl.ssl.context")
local ssl_pkey = require("openssl.pkey")

local function integer(thing)
	return type(thing) == "number" and math.floor(thing) == thing and math.abs(thing) < math.huge
end

local function default_tls_context()
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
		ssl_ctx.OP_NO_COMPRESSION |
		ssl_ctx.OP_SINGLE_ECDH_USE |
		ssl_ctx.OP_NO_SSLv2 |
		ssl_ctx.OP_NO_SSLv3
	)
	ctx:setEphemeralKey(ssl_pkey.new({
		type = "EC",
		curve = "prime256v1",
	}))
	ctx:getStore():addDefaults()
	ctx:setVerify(ssl_ctx.VERIFY_PEER)
	return ctx
end

local function cqueues_wrap(queue, func, ...)
	queue:wrap(function(...)
		assert(xpcall(func, function(err)
			print(err)
			print(debug.traceback())
		end, ...), "wrapped function failed, see trace above")
	end, ...)
end

local function valid_nick(nick)
	-- * TODO: confirm correctness and also correctness of usage
	return type(nick) == "string" and not nick:find("[, \0\r\n]")
end

local function valid_user(user)
	-- * TODO: confirm correctness and also correctness of usage
	return type(user) == "string" and not user:find("[ \0\r\n]")
end

local function valid_pass(pass)
	-- * TODO: confirm correctness and also correctness of usage
	return type(pass) == "string" and not pass:find("[ \0\r\n]")
end

local function valid_host(host)
	-- * TODO: confirm correctness and also correctness of usage
	return type(host) == "string" and not host:find("[ \0\r\n]")
end

local function valid_real(real)
	-- * TODO: confirm correctness and also correctness of usage
	return type(real) == "string" and not real:find("[\0\r\n]")
end

local function valid_command(command)
	-- * TODO: confirm correctness and also correctness of usage
	return type(command) == "string" and not command:lower():find("[^a-z]")
end

local function valid_channel(channel)
	-- * TODO: confirm correctness and also correctness of usage
	return type(channel) == "string" and not channel:find("[, \0\r\n]")
end

local function valid_topic(topic)
	-- * TODO: confirm correctness and also correctness of usage
	return type(topic) == "string" and not topic:find("[ \0\r\n]")
end

local function valid_visibility(visibility)
	-- * TODO: confirm correctness and also correctness of usage
	return type(visibility) == "string" and not visibility:find("[ \0\r\n]")
end

local function valid_list(list)
	-- * TODO: confirm correctness and also correctness of usage
	return type(list) == "string" and not list:find("[\0\r\n]")
end

local function valid_key(key)
	-- * TODO: confirm correctness and also correctness of usage
	return type(key) == "string" and not key:find("[\0\r\n]")
end

local function valid_account(account)
	-- * TODO: confirm correctness and also correctness of usage
	return type(account) == "string" and not account:find("[\0\r\n]")
end

local function valid_message(message)
	-- * TODO: confirm correctness and also correctness of usage
	return type(message) == "string" and not message:find("[\0\r\n]")
end

local function valid_target(target)
	-- * TODO: confirm correctness and also correctness of usage
	return valid_nick(target) or valid_channel(target)
end

local function valid_pinginfo(info)
	-- * TODO: confirm correctness and also correctness of usage
	return type(info) == "string" and not info:find("[\0\r\n]")
end

return {
	integer = integer,
	default_tls_context = default_tls_context,
	cqueues_wrap = cqueues_wrap,
	valid_nick = valid_nick,
	valid_user = valid_user,
	valid_pass = valid_pass,
	valid_host = valid_host,
	valid_real = valid_real,
	valid_command = valid_command,
	valid_channel = valid_channel,
	valid_topic = valid_topic,
	valid_visibility = valid_visibility,
	valid_list = valid_list,
	valid_key = valid_key,
	valid_account = valid_account,
	valid_message = valid_message,
	valid_target = valid_target,
	valid_pinginfo = valid_pinginfo,
	clean = clean,
}
