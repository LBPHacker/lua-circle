package = "circle"
version = "scm-0"

description = {
	summary = "Cqueues IRC Library Extraordinaire",
	homepage = "https://github.com/LBPHacker/lua-circle",
	license = "MIT"
}

source = {
	url = "git+https://github.com/LBPHacker/lua-circle.git"
}

dependencies = {
	"lua >= 5.1",
	"cqueues >= 20190731",
	"luaossl >= 20190731",
}

build = {
	type = "builtin",
	modules = {
		["circle"] = "src/circle/init.lua",
		["circle.client"] = "src/circle/client.lua",
	}
}
