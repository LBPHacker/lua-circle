local util = require("circle.util")

local number_to_name = {
	[ "001" ] = "RPL_WELCOME",
	[ "002" ] = "RPL_YOURHOST",
	[ "003" ] = "RPL_CREATED",
	[ "004" ] = "RPL_MYINFO",
	[ "005" ] = "RPL_BOUNCE",
	[ "200" ] = "RPL_TRACELINK",
	[ "201" ] = "RPL_TRACECONNECTING",
	[ "202" ] = "RPL_TRACEHANDSHAKE",
	[ "203" ] = "RPL_TRACEUNKNOWN",
	[ "204" ] = "RPL_TRACEOPERATOR",
	[ "205" ] = "RPL_TRACEUSER",
	[ "206" ] = "RPL_TRACESERVER",
	[ "207" ] = "RPL_TRACESERVICE",
	[ "208" ] = "RPL_TRACENEWTYPE",
	[ "209" ] = "RPL_TRACECLASS",
	[ "210" ] = "RPL_TRACERECONNECT",
	[ "211" ] = "RPL_STATSLINKINFO",
	[ "212" ] = "RPL_STATSCOMMANDS",
	[ "219" ] = "RPL_ENDOFSTATS",
	[ "221" ] = "RPL_UMODEIS",
	[ "234" ] = "RPL_SERVLIST",
	[ "235" ] = "RPL_SERVLISTEND",
	[ "242" ] = "RPL_STATSUPTIME",
	[ "243" ] = "RPL_STATSOLINE",
	[ "251" ] = "RPL_LUSERCLIENT",
	[ "252" ] = "RPL_LUSEROP",
	[ "253" ] = "RPL_LUSERUNKNOWN",
	[ "254" ] = "RPL_LUSERCHANNELS",
	[ "255" ] = "RPL_LUSERME",
	[ "256" ] = "RPL_ADMINME",
	[ "257" ] = "RPL_ADMINLOC1",
	[ "258" ] = "RPL_ADMINLOC2",
	[ "259" ] = "RPL_ADMINEMAIL",
	[ "261" ] = "RPL_TRACELOG",
	[ "262" ] = "RPL_TRACEEND",
	[ "263" ] = "RPL_TRYAGAIN",
	[ "301" ] = "RPL_AWAY",
	[ "302" ] = "RPL_USERHOST",
	[ "303" ] = "RPL_ISON",
	[ "305" ] = "RPL_UNAWAY",
	[ "306" ] = "RPL_NOWAWAY",
	[ "311" ] = "RPL_WHOISUSER",
	[ "312" ] = "RPL_WHOISSERVER",
	[ "313" ] = "RPL_WHOISOPERATOR",
	[ "314" ] = "RPL_WHOWASUSER",
	[ "315" ] = "RPL_ENDOFWHO",
	[ "317" ] = "RPL_WHOISIDLE",
	[ "318" ] = "RPL_ENDOFWHOIS",
	[ "319" ] = "RPL_WHOISCHANNELS",
	[ "321" ] = "RPL_LISTSTART",
	[ "322" ] = "RPL_LIST",
	[ "323" ] = "RPL_LISTEND",
	[ "324" ] = "RPL_CHANNELMODEIS",
	[ "325" ] = "RPL_UNIQOPIS",
	[ "330" ] = "RPL_WHOISLOGGEDIN",
	[ "331" ] = "RPL_NOTOPIC",
	[ "332" ] = "RPL_TOPIC",
	[ "341" ] = "RPL_INVITING",
	[ "342" ] = "RPL_SUMMONING",
	[ "346" ] = "RPL_INVITELIST",
	[ "347" ] = "RPL_ENDOFINVITELIST",
	[ "348" ] = "RPL_EXCEPTLIST",
	[ "349" ] = "RPL_ENDOFEXCEPTLIST",
	[ "351" ] = "RPL_VERSION",
	[ "352" ] = "RPL_WHOREPLY",
	[ "353" ] = "RPL_NAMREPLY",
	[ "364" ] = "RPL_LINKS",
	[ "365" ] = "RPL_ENDOFLINKS",
	[ "366" ] = "RPL_ENDOFNAMES",
	[ "367" ] = "RPL_BANLIST",
	[ "368" ] = "RPL_ENDOFBANLIST",
	[ "369" ] = "RPL_ENDOFWHOWAS",
	[ "371" ] = "RPL_INFO",
	[ "372" ] = "RPL_MOTD",
	[ "374" ] = "RPL_ENDOFINFO",
	[ "375" ] = "RPL_MOTDSTART",
	[ "376" ] = "RPL_ENDOFMOTD",
	[ "381" ] = "RPL_YOUREOPER",
	[ "382" ] = "RPL_REHASHING",
	[ "383" ] = "RPL_YOURESERVICE",
	[ "391" ] = "RPL_TIME",
	[ "392" ] = "RPL_USERSSTART",
	[ "393" ] = "RPL_USERS",
	[ "394" ] = "RPL_ENDOFUSERS",
	[ "395" ] = "RPL_NOUSERS",
	[ "401" ] = "ERR_NOSUCHNICK",
	[ "402" ] = "ERR_NOSUCHSERVER",
	[ "403" ] = "ERR_NOSUCHCHANNEL",
	[ "404" ] = "ERR_CANNOTSENDTOCHAN",
	[ "405" ] = "ERR_TOOMANYCHANNELS",
	[ "406" ] = "ERR_WASNOSUCHNICK",
	[ "407" ] = "ERR_TOOMANYTARGETS",
	[ "408" ] = "ERR_NOSUCHSERVICE",
	[ "409" ] = "ERR_NOORIGIN",
	[ "411" ] = "ERR_NORECIPIENT",
	[ "412" ] = "ERR_NOTEXTTOSEND",
	[ "413" ] = "ERR_NOTOPLEVEL",
	[ "414" ] = "ERR_WILDTOPLEVEL",
	[ "415" ] = "ERR_BADMASK",
	[ "421" ] = "ERR_UNKNOWNCOMMAND",
	[ "422" ] = "ERR_NOMOTD",
	[ "423" ] = "ERR_NOADMININFO",
	[ "424" ] = "ERR_FILEERROR",
	[ "431" ] = "ERR_NONICKNAMEGIVEN",
	[ "432" ] = "ERR_ERRONEUSNICKNAME",
	[ "433" ] = "ERR_NICKNAMEINUSE",
	[ "436" ] = "ERR_NICKCOLLISION",
	[ "437" ] = "ERR_UNAVAILRESOURCE",
	[ "441" ] = "ERR_USERNOTINCHANNEL",
	[ "442" ] = "ERR_NOTONCHANNEL",
	[ "443" ] = "ERR_USERONCHANNEL",
	[ "444" ] = "ERR_NOLOGIN",
	[ "445" ] = "ERR_SUMMONDISABLED",
	[ "446" ] = "ERR_USERSDISABLED",
	[ "451" ] = "ERR_NOTREGISTERED",
	[ "461" ] = "ERR_NEEDMOREPARAMS",
	[ "462" ] = "ERR_ALREADYREGISTRED",
	[ "463" ] = "ERR_NOPERMFORHOST",
	[ "464" ] = "ERR_PASSWDMISMATCH",
	[ "465" ] = "ERR_YOUREBANNEDCREEP",
	[ "466" ] = "ERR_YOUWILLBEBANNED",
	[ "467" ] = "ERR_KEYSET",
	[ "471" ] = "ERR_CHANNELISFULL",
	[ "472" ] = "ERR_UNKNOWNMODE",
	[ "473" ] = "ERR_INVITEONLYCHAN",
	[ "474" ] = "ERR_BANNEDFROMCHAN",
	[ "475" ] = "ERR_BADCHANNELKEY",
	[ "476" ] = "ERR_BADCHANMASK",
	[ "477" ] = "ERR_NOCHANMODES",
	[ "478" ] = "ERR_BANLISTFULL",
	[ "481" ] = "ERR_NOPRIVILEGES",
	[ "482" ] = "ERR_CHANOPRIVSNEEDED",
	[ "483" ] = "ERR_CANTKILLSERVER",
	[ "484" ] = "ERR_RESTRICTED",
	[ "485" ] = "ERR_UNIQOPPRIVSNEEDED",
	[ "491" ] = "ERR_NOOPERHOST",
	[ "501" ] = "ERR_UMODEUNKNOWNFLAG",
	[ "502" ] = "ERR_USERSDONTMATCH",
	[ "671" ] = "RPL_WHOISSECURE",
}

local msgno = {}
for key, value in pairs(number_to_name) do
	msgno[key] = value
	msgno[value] = key
end

local function parse_line(line)
	local command, prefix
	local params = {}
	do
		local rest
		prefix, rest = line:match("^:([^ ]+) (.*)$")
		if prefix then
			line = rest
		end
	end
	do
		local rest
		command, rest = line:match("^(%d%d%d)(.*)$")
		if not command then
			command, rest = line:match("^([A-Za-z]+)(.*)$")
		end
		if not command then
			return nil, "no command"
		end
		line = rest
	end
	while #params < 14 do
		local param, rest = line:match("^ ([^: ][^ ]*)(.*)$")
		if not param then
			break
		end
		table.insert(params, param)
		line = rest
	end
	do
		local trailing = line:match(#params == 14 and "^ :?(.*)$" or "^ :(.*)$")
		if trailing then
			table.insert(params, trailing)
		end
		line = ""
	end
	if line ~= "" then
		return nil, "expected end of line"
	end
	return command:lower(), params, prefix
end

local function build_line(limit, command, middles, trailing, prefix)
	local collect = {}
	if prefix then
		table.insert(collect, ":")
		table.insert(collect, prefix)
		table.insert(collect, " ")
	end
	table.insert(collect, command)
	for ix = 1, #middles do
		table.insert(collect, " ")
		table.insert(collect, middles[ix])
	end
	if trailing then
		table.insert(collect, " :")
		table.insert(collect, trailing)
	end
	table.insert(collect, "\r\n")
	local line = table.concat(collect)
	if #line > limit then
		return nil, "message size limit exceeded"
	end
	return line
end

local command_checks = {}

function command_checks.ping(server, server2)
	if not util.valid_pinginfo(server) then
		return nil, "PING command with invalid server field"
	end
	if server2 ~= nil and not util.valid_pinginfo(server2) then
		return nil, "PING command with invalid server2 field"
	end
	return true
end

function command_checks.privmsg(target, message)
	if not util.valid_target(target) then
		return nil, "PRIVMSG command with invalid target field"
	end
	if not util.valid_message(message) then
		return nil, "PRIVMSG command with invalid message field"
	end
	return true
end

function command_checks.notice(target, message)
	if not util.valid_target(target) then
		return nil, "NOTICE command with invalid target field"
	end
	if not util.valid_message(message) then
		return nil, "NOTICE command with invalid message field"
	end
	return true
end

function command_checks.nick(nick)
	if not util.valid_nick(nick) then
		return nil, "NICK command with invalid nick field"
	end
	return true
end

function command_checks.RPL_NAMREPLY(visibility, channel, list)
	if not util.valid_visibility(visibility) then
		-- * TODO: visibilities?
		return nil, "RPL_NAMREPLY command with invalid visibility field"
	end
	if not util.valid_channel(channel) then
		return nil, "RPL_NAMREPLY command with invalid channel field"
	end
	if not util.valid_list(list) then
		return nil, "RPL_NAMREPLY command with invalid list field"
	end
	for entry in list:gmatch("[^ ]+") do

	end
	return true
end

function command_checks.RPL_TRYAGAIN(what)
	if not util.valid_command(what) then
		return nil, "RPL_TRYAGAIN command with invalid command field"
	end
	return true
end

function command_checks.RPL_ENDOFNAMES(channel)
	if not util.valid_channel(channel) then
		return nil, "RPL_ENDOFNAMES command with invalid channel field"
	end
	return true
end

function command_checks.RPL_TOPIC(channel, topic)
	if not util.valid_channel(channel) then
		return nil, "RPL_TOPIC command with invalid channel field"
	end
	if not util.valid_topic(topic) then
		return nil, "RPL_TOPIC command with invalid topic field"
	end
	return true
end

function command_checks.RPL_NOTOPIC(channel)
	if not util.valid_channel(channel) then
		return nil, "RPL_NOTOPIC command with invalid channel field"
	end
	return true
end

function command_checks.RPL_WHOISUSER(nick, user, host, _, real)
	if not util.valid_nick(nick) then
		return nil, "RPL_WHOISUSER command with invalid nick field"
	end
	if not util.valid_user(user) then
		return nil, "RPL_WHOISUSER command with invalid user field"
	end
	if not util.valid_host(host) then
		return nil, "RPL_WHOISUSER command with invalid host field"
	end
	if not util.valid_real(real) then
		return nil, "RPL_WHOISUSER command with invalid real field"
	end
	return true
end

function command_checks.RPL_WHOISSECURE(nick)
	if not util.valid_nick(nick) then
		return nil, "RPL_WHOISSECURE command with invalid nick field"
	end
	return true
end

function command_checks.RPL_WHOISLOGGEDIN(nick, account)
	if not util.valid_nick(nick) then
		return nil, "RPL_WHOISLOGGEDIN command with invalid nick field"
	end
	if not util.valid_account(account) then
		return nil, "RPL_WHOISLOGGEDIN command with invalid account field"
	end
	return true
end

function command_checks.RPL_ENDOFWHOIS(nick)
	if not util.valid_nick(nick) then
		return nil, "RPL_ENDOFWHOIS command with invalid nick field"
	end
	return true
end

local command_check_funcs = {}
for key, value in pairs(command_checks) do
	command_check_funcs[msgno[key] or key] = value
end

local function check_command(command, ...)
	local check = command_check_funcs[command]
	if check then
		return check(...)
	end
	return true
end

local mappings = {}

for name, init in pairs({
	["ascii"] = {
		uppercase = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ]==],
		lowercase = [==[abcdefghijklmnopqrstuvwxyz]==],
	},
	["rfc1459"] = {
		uppercase = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\~]==],
		lowercase = [==[abcdefghijklmnopqrstuvwxyz{}|^]==],
	},
	["rfc1459-strict"] = {
		uppercase = [==[ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\]==],
		lowercase = [==[abcdefghijklmnopqrstuvwxyz{}|]==],
	},
}) do
	local lower = {}
	for _, ch in utf8.codes(init.lowercase) do
		table.insert(lower, ch)
	end
	local upper = {}
	for _, ch in utf8.codes(init.uppercase) do
		table.insert(upper, ch)
	end
	assert(#lower == #upper)
	local mapping = {}
	for i = 1, #lower do
		mapping[upper[i]] = lower[i]
	end
	mappings[name] = mapping
end

local function lower(mapping, str)
	local out = {}
	local ok, err = pcall(function()
		for _, ch in utf8.codes(str) do
			table.insert(out, utf8.char(mapping[ch] or ch))
		end
	end)
	if not ok then
		return nil, err
	end
	return table.concat(out)
end

return {
	msgno = msgno,
	parse_line = parse_line,
	build_line = build_line,
	check_command = check_command,
	mappings = mappings,
	lower = lower,
}
