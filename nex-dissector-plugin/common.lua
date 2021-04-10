local md5 = require("md5")
local string_char = string.char
local table_concat = table.concat

function deepcopy(orig)
	local orig_type = type(orig)
	local copy
	if orig_type == 'table' then
		copy = {}
		for orig_key, orig_value in next, orig, nil do
			copy[deepcopy(orig_key)] = deepcopy(orig_value)
		end
		setmetatable(copy, deepcopy(getmetatable(orig)))
	else -- number, string, boolean, etc
		copy = orig
	end
	return copy
end

function gen_kerb_key(pid, password)
	kerb_key = password
	a = 65000 + (pid % 1024)
	for i = 1, a do
		kerb_key = md5.sum(kerb_key)
	end
	return kerb_key
end

function string.fromhex(str)
	return (str:gsub('..', function (cc)
				return string.char(tonumber(cc, 16))
			end))
end

function string.tohex(str)
	return (str:gsub('.', function (c)
				return string.format('%02X', string.byte(c))
			end))
end

function int_from_bytes(bytearr)
	local out = 0
	for i = 0, bytearr:len() - 1 do
		out = bit.bor(out, bit.lshift(bytearr:get_index(i), i * 8))
	end
	return out
end

PORT_SERVER, PORT_CLIENT = 0xa1, 0xaf
TYPE_SYN, TYPE_CONNECT, TYPE_DATA, TYPE_DISCONNECT, TYPE_PING = 0, 1, 2, 3, 4

ports = {
	[PORT_SERVER] = "Server",
	[PORT_CLIENT] = "Client"
}

pkt_types = {
	[TYPE_SYN] = "SYN",
	[TYPE_CONNECT] = "CONNECT",
	[TYPE_DATA] = "DATA",
	[TYPE_DISCONNECT] = "DISCONNECT",
	[TYPE_PING] = "PING"
}
