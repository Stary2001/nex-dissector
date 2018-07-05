local nex_proto = Proto("nex", "NEX")
local prudp_proto

local protos = 
{
	[0x01] = {
		["name"] = "Remote log device",
		["methods"] = {}
	},

	[0x03] = {
		["name"] = "NAT traversal",
		["methods"] = {}
	},

	[0x0A] = {
		["name"] = "Authentication",
		["methods"] = {
			[0x01] = "Login",
			[0x02] = "LoginEx",
			[0x03] = "RequestTicket",
			[0x04] = "GetPID",
			[0x05] = "GetName",
			[0x06] = "LoginWithContext"
		}
	},

	[0x0B] = {
		["name"] = "Secure connection",
		["methods"] = {
			[1] = "Register",
			[2] = "RequestConnectionData",
			[3] = "RequestUrls",
			[4] = "RegisterEx",
			[5] = "TestConnectivity",
			[6] = "UpdateURLs",
			[7] = "ReplaceURL",
			[8] = "SendReport"
		}
	},

	[0x0E] = {
		["name"] = "Notification events",
		["methods"] = {}
	},

	[0x10] = {
		["name"] = "Simple authentication",
		["methods"] = {}
	},

	[0x11] = {
		["name"] = "Siege",
		["methods"] = {}
	},

	[0x12] = {
		["name"] = "Health",
		["methods"] = {}
	},

	[0x13] = {
		["name"] = "Monitoring",
		["methods"] = {}
	},

	[0x14] = {
		["name"] = "Friends",
		["methods"] = {}
	},

	[0x15] = {
		["name"] = "Match making",
		["methods"] = {}
	},

	[0x17] = {
		["name"] = "Messaging",
		["methods"] = {}
	},

	[0x18] = {
		["name"] = "Persistent store",
		["methods"] = {}
	},

	[0x19] = {
		["name"] = "Account management",
		["methods"] = {}
	},

	[0x1B] = {
		["name"] = "Message delivery",
		["methods"] = {}
	},

	[0x1C] = {
		["name"] = "Client settings",
		["methods"] = {}
	},

	[0x1D] = {
		["name"] = "Ubi account management",
		["methods"] = {}
	},

	[0x1E] = {
		["name"] = "Geo localization",
		["methods"] = {}
	},

	[0x1F] = {
		["name"] = "News",
		["methods"] = {}
	},

	[0x23] = {
		["name"] = "Privileges",
		["methods"] = {}
	},

	[0x24] = {
		["name"] = "Tracking / telemetry",
		["methods"] = {}
	},

	[0x27] = {
		["name"] = "Localization",
		["methods"] = {}
	},

	[0x2A] = {
		["name"] = "Game session",
		["methods"] = {}
	},

	[0x2C] = {
		["name"] = "Sub account management",
		["methods"] = {}
	},

	[0x2D] = {
		["name"] = "IP to location",
		["methods"] = {}
	},

	[0x2E] = {
		["name"] = "IP to location admin",
		["methods"] = {}
	},

	[0x2F] = {
		["name"] = "Ubi friends",
		["methods"] = {}
	},

	[0x30] = {
		["name"] = "Skill rating",
		["methods"] = {}
	},

	[0x31] = {
		["name"] = "Uplay win",
		["methods"] = {}
	},

	[0x32] = {
		["name"] = "Match making (extension)",
		["methods"] = {}
	},

	[0x33] = {
		["name"] = "Title storage",
		["methods"] = {}
	},

	[0x35] = {
		["name"] = "User storage",
		["methods"] = {}
	},

	[0x37] = {
		["name"] = "Player stats",
		["methods"] = {}
	},

	[0x47] = {
		["name"] = "Offline game notifications",
		["methods"] = {}
	},

	[0x48] = {
		["name"] = "User account management",
		["methods"] = {}
	},

	[0x54] = {
		["name"] = "Siege admin",
		["methods"] = {}
	},

	[0x64] = {
		["name"] = "Nintendo notification events",
		["methods"] = {}
	},

	[0x65] = {
		["name"] = "Friends (3DS)",
		["methods"] = {
			[1] = "UpdateProfile",
			[2] = "UpdateMii",
			[3] = "UpdateMiiList",
			[4] = "UpdatePlayedGames",
			[5] = "UpdatePreference",
			[6] = "GetFriendMii",
			[7] = "unk_7",
			[8] = "unk_8",
			[9] = "unk_9",
			[10] = "GetFriendRelationships",
			[11] = "AddFriendByPrincipalID",
			[12] = "unk_12",
			[13] = "unk_13",
			[14] = "unk_14",
			[15] = "GetAllFriends",
			[16] = "unk_16",
			[17] = "SyncFriend",
			[18] = "UpdatePresence",
			[19] = "UpdateFavoriteGameKey",
			[20] = "UpdateComment",
			[21] = "unk_21",
			[22] = "GetFriendPresence",
			[23] = "unk_23",
			[24] = "GetFriendPicture",
			[25] = "GetFriendPersistentInfo",
			[26] = "unk_26"
		}
	},

	[0x66] = {
		["name"] = "Friends (Wii U)",
		["methods"] = {}
	},

	[0x6D] = {
		["name"] = "Matchmake extension",
		["methods"] = {}
	},

	[0x6E] = {
		["name"] = "Utility",
		["methods"] = {}
	},

	[0x70] = {
		["name"] = "Ranking",
		["methods"] = {}
	},

	[0x73] = {
		["name"] = "Data store",
		["methods"] = {}
	},

	[0x7A] = {
		["name"] = "Ranking 2",
		["methods"] = {}
	}
}

local F = nex_proto.fields
F.size = ProtoField.uint32("nex.size", "Big ass size", base.HEX)
F.proto = ProtoField.uint8("nex.proto", "Protocol", base.HEX, nil, 0x7f)
F.call_id = ProtoField.uint32("nex.call_id", "Call ID", base.HEX)
F.method_id = ProtoField.uint32("nex.method_id", "Method ID", base.HEX, nil, 0x7fff)

local f_type = Field.new("prudp.type")
local f_payload = Field.new("prudp.payload")
local f_ack = Field.new("prudp.ack")

function resolve(proto_id, method_id)
	local proto_name, method_name
	proto = protos[proto_id]
	if proto ~= nil then
		proto_name = proto['name']
		if proto['methods'][method_id] ~= nil then
			method_name = proto['methods'][method_id]
		else
			method_name = "Unknown_"..string.format("0x%04x", method_id)
		end
	else
		proto_name = string.format("0x%02x", proto_id)
		method_name = string.format("0x%04x", method_id)
	end
	return proto_name, method_name
end

function nex_proto.dissector(buf, pinfo, tree)
	prudp_proto:call(buf, pinfo, tree)
	
	local payload_field_type = f_type()
	local payload_field_ack = f_ack()
	if payload_field_type() ~= 2 or payload_field_ack() then
		return
	end
	
	local payload_field_info = f_payload()
	local payload = payload_field_info.range

	local subtreeitem = tree:add(nex_proto, buf)
	
	local pkt_size = payload(0,4):le_uint()
	subtreeitem:add_le(F.size, payload(0,4))
	
	local pkt_proto_id = payload(4,1):le_uint()
	subtreeitem:add_le(F.proto, payload(4,1))

	local request = bit.band(pkt_proto_id, 0x80) ~= 0
	pkt_proto_id = bit.band(pkt_proto_id, bit.bnot(0x80))

	local info
	if request then
		info = "Request"

		local pkt_call_id = payload(5,4):le_uint()
		subtreeitem:add_le(F.call_id, payload(5,4))

		local pkt_method_id = payload(9,4):le_uint()
		subtreeitem:add_le(F.method_id, payload(9,4))
		
		local proto_name, method_name = resolve(pkt_proto_id, pkt_method_id)
		info = info .. string.format(" %s->%s, call=0x%08x", proto_name, method_name, pkt_call_id)
	else
		info = "Response"

		local pkt_success = payload(5,1):le_uint()
		if pkt_success == 1 then
			local pkt_call_id = payload(6,4):le_uint()
			subtreeitem:add_le(F.call_id, payload(6,4))
			local pkt_method_id = bit.band(payload(0xa, 4):le_uint(), bit.bnot(0x8000))
			subtreeitem:add_le(F.method_id, payload(0xa,4))

			local proto_name, method_name = resolve(pkt_proto_id, pkt_method_id)
			info = info .. string.format(" Success %s->%s call=%08x", proto_name, method_name, pkt_call_id)
		else
			local pkt_err = payload(6,4):le_uint()
			local pkt_call_id = payload(0xa, 4):le_uint()
			subtreeitem:add_le(F.call_id, payload(0xa,4))

			info = info .. string.format(" Failure, err=%08x, call=0x%08x", pkt_err, pkt_call_id)
		end
	end

	pinfo.cols.info = "NEX " .. info
end

udp_table = DissectorTable.get("udp.port")
prudp_proto = udp_table:get_dissector(60000)
udp_table:add(60000, nex_proto)