package = "circle"
version = "scm-0"

description = {
	summary = "Cqueues Internet Relay Chat Library for Everyone",
	homepage = "https://github.com/LBPHacker/lua-circle",
	license = "MIT"
}

source = {
	url = "git+https://github.com/LBPHacker/lua-circle.git"
}

dependencies = {
	"lua >= 5.3",
	"cqueues >= 20161214",
	"luaossl >= 20161208",
}

build = {
	type = "builtin",
	modules = {
		["circle.client"] = "src/circle/client/init.lua",
		["circle.util"] = "src/circle/util.lua",
		["circle.proto"] = "src/circle/proto.lua",
	}
}
