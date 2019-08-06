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
	return command, params, prefix
end

local function valid_user(str)
	return not str:find("[^\1-\9\11\12\14-\31\33-\63\65-\255]")
end

local function valid_nick(str)
	return str:find("^[A-Za-z%[%]\\`_%^{|}][A-Za-z0-9%[%]\\`_%^{|}%-]*$")
end

local function valid_trailing(str)
	return not str:find("[^\1-\9\11\12\14-\255]")
end

return {
	parse_line = parse_line,
	valid_user = valid_user,
	valid_nick = valid_nick,
	valid_pass = valid_trailing,
	valid_real = valid_trailing
}
