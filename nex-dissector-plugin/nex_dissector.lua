local rc4 = require("rc4")
local common = require("common")

require("prudp_v0_dissector")
require("prudp_v1_dissector")
require("fragmentation")

local hmac = require("hmac")
local md5 = require("md5")

-- See: https://github.com/Kinnay/NintendoClients/wiki/RMC-Protocol

local access_key_table = {
	["9f2b4678"] = "SMM",
	["6f599f81"] = "Splatoon",
	-- todo: for other game specific protocols...
}

function sig_v0(access_key, secure_key, pkt_seq, fragment, raw_payload)
	seq = string.char(bit.band(pkt_seq, 0xff)) .. string.char(bit.rshift(bit.band(pkt_seq, 0xff00), 8))
	fragment = string.char(fragment)
	local data = secure_key .. seq ..  fragment .. raw_payload:raw()

	local key = md5.sum(access_key)
	return hmac.compute(key, data, md5.sum, 64):sub(1,4)
end

function sig_v1(access_key, packet_header, secure_key, conn_sig, optional_data, raw_payload)
	access_key_sum = 0
	for i=1,#access_key do
		access_key_sum = access_key_sum + access_key:byte(i)
	end

	local data = packet_header:raw() .. secure_key .. raw_bytes_from_int(access_key_sum) .. conn_sig:raw() .. optional_data .. raw_payload:raw()

	local key = md5.sum(access_key)
	return hmac.compute(key, data, md5.sum, 64)
end

function version_gt_eq(a, b)
	if a[1] > b[1] then
		return true
	elseif a[1] < b[1] then
		return false
	elseif a[2] > b[2] then -- first one equal
		return true
	elseif a[2] < b[2] then
		return true
	elseif a[3] > b[3] then -- first 2 equal
		return true
	elseif a[3] < b[3] then
		return false
	else
		return true
	end
end

local nex_proto = Proto("nex", "NEX")
local nexraw_proto = Proto("nexraw", "NEXraw")
local prudp_proto

local SECURE_KEYS = {}
local CONNECTIONS = {}
local dec_packets = {}

local rawnex_conn = {
						[PORT_SERVER] = 0,
						[PORT_CLIENT] = 0,
						['client_conn_sig'] = 0
					}

function find_connection(pinfo)
	a = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port)
	b = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port)
	if CONNECTIONS[a] ~= nil then
		return CONNECTIONS[a], a
	elseif CONNECTIONS[b] ~= nil then
		return CONNECTIONS[b], b
	end
	return rawnex_conn, 0
end

function set_connection(pinfo, t)
	-- Complete connections with both src+dst port infos.
	a = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port)
	-- Prevent duplicate connection packets from messing things up
	if CONNECTIONS[a] == nil then
		CONNECTIONS[a] = t
	end
end

local KERB_KEYS = {}

local basedir = ( USER_DIR or persconffile_path() )
local update_keyfile = false

for line in io.lines(basedir .. "nex-keys.txt") do
	local pid, pass = string.match(line, '^(.-):(.+)$')
	if pid ~= nil and pass ~= nil then
		pid = tonumber(pid)
		if #pass ~= 32 then
			KERB_KEYS[pid] = gen_kerb_key(pid, pass)
			update_keyfile = true
		else
			KERB_KEYS[pid] = string.fromhex(pass)
		end
	end
end

if update_keyfile then
	local f = io.open(basedir .. "nex-keys.txt", "w")
	for pid, key in pairs(KERB_KEYS) do
		f:write(tostring(pid) .. ":" .. string.tohex(key) .. "\n")
	end
	update_keyfile = false
end

function script_path()
   local str = debug.getinfo(2, "S").source:sub(2)
   return str:match("(.*[/\\])")
end

F = nex_proto.fields
_G["F"] = F -- apparently this isn't global enough >:(
_G["version_gt_eq"] = version_gt_eq
protos, nested_protos = dofile(script_path() .. "protos.inc")

F.raw_payload = ProtoField.bytes("nex.rawpayload", "Decrypted PRUDP payload")

F.size = ProtoField.uint32("nex.size", "Big ass size", base.HEX)
F.proto = ProtoField.uint8("nex.proto", "Protocol", base.HEX, nil, 0x7f)
F.call_id = ProtoField.uint32("nex.call_id", "Call ID", base.HEX)
F.method_id = ProtoField.uint32("nex.method_id", "Method ID", base.HEX, nil, 0x7fff)
F.payload = ProtoField.bytes("nex.payload", "Payload")

local f_src_v0 = Field.new("prudpv0.src")
local f_type_v0 = Field.new("prudpv0.type")
local f_ack_v0 = Field.new("prudpv0.ack")
local f_multi_ack_v0 = Field.new("prudpv0.multi_ack")
local f_seq_v0 = Field.new("prudpv0.seq")
local f_payload_v0 = Field.new("prudpv0.payload")
local f_defragmented_payload_v0 = Field.new("prudpv0.defragmented_payload")
local f_session_id_v0 = Field.new("prudpv0.session")
local f_packet_sig_v0 = Field.new("prudpv0.packet_sig")
local f_fragment_v0 = Field.new("prudpv0.fragment")
local f_conn_sig_v0 = Field.new("prudpv0.conn_sig")

local f_src_v1 = Field.new("prudpv1.src")
local f_type_v1 = Field.new("prudpv1.type")
local f_ack_v1 = Field.new("prudpv1.ack")
local f_multi_ack_v1 = Field.new("prudpv1.multi_ack")
local f_seq_v1 = Field.new("prudpv1.seq")
local f_payload_v1 = Field.new("prudpv1.payload")
local f_defragmented_payload_v1 = Field.new("prudpv1.defragmented_payload")
local f_session_id_v1 = Field.new("prudpv1.session")
local f_packet_sig_v1 = Field.new("prudpv1.packet_sig")
local f_fragment_v1 = Field.new("prudpv1.fragment")
local f_conn_sig_v1 = Field.new("prudpv1.connection_signature")

function resolve(conn, proto_id, method_id)
	local proto_name, method_name
	p = protos[proto_id]
	if p ~= nil then
		proto_name = p['name']
		if p['methods'][method_id] ~= nil then
			method_name = p['methods'][method_id]['name']
		else
			if conn['game'] ~= nil and nested_protos[conn['game']] ~= nil then
				game_proto = nested_protos[conn['game']][proto_id]
				if game_proto ~= nil then
					proto_name = proto_name .. "(" .. game_proto['name'] .. ")"
					if game_proto['methods'][method_id] ~= nil then
						method_name = game_proto['methods'][method_id]['name']
					else
						method_name = "Unknown_"..string.format("0x%04x", method_id)
					end
				else
					method_name = "Unknown_"..string.format("0x%04x", method_id)
				end
			else
				method_name = "Unknown_"..string.format("0x%04x", method_id)
			end
		end
	else
		proto_name = string.format("0x%02x", proto_id)
		method_name = string.format("0x%04x", method_id)
	end
	return proto_name, method_name
end

function dissect_req(conn, tree, tvb, proto_id, method_id)
	if protos[proto_id] ~= nil then
		p = protos[proto_id]
		if p['methods'][method_id] ~= nil and p['methods'][method_id]['request'] ~= nil then
			p['methods'][method_id]['request'](conn, tree, tvb)
		else
			if conn['game'] ~= nil and nested_protos[conn['game']] ~= nil then
				game_proto = nested_protos[conn['game']][proto_id]
				if game_proto ~= nil then
					if game_proto['methods'][method_id] ~= nil and game_proto['methods'][method_id]['request'] ~= nil then
						game_proto['methods'][method_id]['request'](conn, tree, tvb)
					end
				end
			end
		end
	end
end

function dissect_resp(conn, tree, tvb, proto_id, method_id)
	if protos[proto_id] ~= nil then
		p = protos[proto_id]
		if p['methods'][method_id] ~= nil and p['methods'][method_id]['response'] ~= nil then
			p['methods'][method_id]['response'](conn, tree, tvb)
		else
			if conn['game'] ~= nil and nested_protos[conn['game']] ~= nil then
				game_proto = nested_protos[conn['game']][proto_id]
				if game_proto ~= nil then
					if game_proto['methods'][method_id] ~= nil and game_proto['methods'][method_id]['response'] ~= nil then
						game_proto['methods'][method_id]['response'](conn, tree, tvb)
					end
				end
			end
		end
	end
end

function nex_proto.dissector(buf, pinfo, tree)
	local pkt_src
	local pkt_type
	local pkt_flag_ack
	local pkt_seq
	local pkt_session_id

	local payload, raw_payload
	local payload_field_info

	version = 0

	if buf(0, 2):le_uint() == 0xd0ea then
		version = 1

		Dissector.get("prudpv1"):call(buf, pinfo, tree)
		pkt_src = f_src_v1()()
		pkt_type = f_type_v1()()
		pkt_flag_ack = f_ack_v1()()
		pkt_flag_multi_ack = f_multi_ack_v1()()
		pkt_seq = f_seq_v1()()
		pkt_session_id = f_session_id_v1()()
		pkt_signature = f_packet_sig_v1()()
		if pkt_type == TYPE_DATA then
			payload_field_info = f_defragmented_payload_v1()
		else
			payload_field_info = f_payload_v1()
		end

		if f_conn_sig_v1() then
			pkt_conn_sig = f_conn_sig_v1()()
		end
	else
		Dissector.get("prudpv0"):call(buf, pinfo, tree)
		pkt_src = f_src_v0()()
		pkt_type = f_type_v0()()
		pkt_flag_ack = f_ack_v0()()
		pkt_flag_multi_ack = f_multi_ack_v0()()
		pkt_seq = f_seq_v0()()
		pkt_session_id = f_session_id_v0()()
		pkt_signature = f_packet_sig_v0()()
		if pkt_type == TYPE_DATA then
			payload_field_info = f_defragmented_payload_v0()
		else
			payload_field_info = f_payload_v0()
		end

		if f_conn_sig_v0() then
			pkt_conn_sig = f_conn_sig_v0()()
		end
	end

	if payload_field_info then
		raw_payload = payload_field_info.range
	end

	if pkt_type == TYPE_SYN and pkt_flag_ack then
		local partial_conn_id = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst)
		if CONNECTIONS[partial_conn_id] then
			CONNECTIONS[partial_conn_id]['server_conn_sig'] = pkt_conn_sig
		end
	end
	
	if pkt_type == TYPE_CONNECT and not pkt_flag_ack then
		-- This should be client->server. We knew the servers's IP and port, as well as the client's IP.
		local partial_conn_id = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src)
		local partial_conn = CONNECTIONS[partial_conn_id]
		local conn, conn_id = find_connection(pinfo)

		if SECURE_KEYS[partial_conn_id] ~= nil then
			if raw_payload then
				local first_buff_size = raw_payload(0, 4):le_uint() + 4
				local check_buffer_size = raw_payload(first_buff_size, 4):le_uint()
				local check_buffer = raw_payload(first_buff_size + 4, check_buffer_size)

				local check_contents = check_buffer(0, check_buffer:len() - 16)
				local check_hmac = check_buffer(check_buffer:len() - 16, 16)
				local secure_key = SECURE_KEYS[partial_conn_id]
				local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
				local pid = int_from_bytes(check_decrypted(0,4))
				if pid ~= partial_conn['nonsecure_pid'] then
					secure_key = secure_key:sub(1,16)
					local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
					local pid = int_from_bytes(check_decrypted(0,4))

					if pid ~= partial_conn['nonsecure_pid'] then
						print("Secure key is fucked!")
					end
				end

				CONNECTIONS[conn_id] = {
					[PORT_SERVER] = rc4.new_ks(secure_key),
					[PORT_CLIENT] = rc4.new_ks(secure_key),
					['nonsecure_pid'] = partial_conn['nonsecure_pid'],
					['has_struct_headers'] = partial_conn['has_struct_headers'],
					['prudp_version'] = partial_conn['prudp_version'],
					['nex_version'] = partial_conn['nex_version'],
					['server_conn_sig'] = partial_conn['server_conn_sig'],
					['client_conn_sig'] = pkt_conn_sig,
				}
				SECURE_KEYS[conn_id] = secure_key
				CONNECTIONS[partial_conn_id] = nil
				SECURE_KEYS[partial_conn_id] = nil
			else
				print("Secure connection CONNECT without payload?")
				CONNECTIONS[conn_id] = {
					[PORT_SERVER] = rc4.new_ks("CD&ML"),
					[PORT_CLIENT] = rc4.new_ks("CD&ML"),
					['nonsecure_pid'] = partial_conn['nonsecure_pid'],
					['has_struct_headers'] = partial_conn['has_struct_headers'],
					['prudp_version'] = partial_conn['prudp_version'],
					['nex_version'] = partial_conn['nex_version'],
					['server_conn_sig'] = partial_conn['server_conn_sig'],
					['client_conn_sig'] = pkt_conn_sig,
				}
				SECURE_KEYS[conn_id] = secure_key
				CONNECTIONS[partial_conn_id] = nil
				SECURE_KEYS[partial_conn_id] = nil
			end
		else
			set_connection(pinfo, {
					[PORT_SERVER] = rc4.new_ks("CD&ML"),
					[PORT_CLIENT] = rc4.new_ks("CD&ML"),
					['client_conn_sig'] = pkt_conn_sig,
				})
		end
	end
	if pkt_type == TYPE_CONNECT and pkt_flag_ack and pkt_src ~= PORT_SERVER then
		-- This should be server->client connection ack, but with a mismatched pkt_src. Fix up the keys
		conn, conn_id = find_connection(pinfo)
		conn[pkt_src] = conn[PORT_SERVER]
		print("Mismatched server pkt_src " .. pkt_src .. ", correcting key...")
	end

	if pkt_type == TYPE_DATA and not pkt_flag_ack and not pkt_flag_multi_ack then
		if raw_payload then
			local conn
			local conn_id

			conn, conn_id = find_connection(pinfo)

			-- I hate this. Please come up with a better method.
			pkt_id = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .."-".. tostring(pkt_seq) .. "-" .. tostring(pkt_session_id)
			if dec_packets[pkt_id] == nil then
				dec_packets[pkt_id] = rc4.crypt(conn[pkt_src], raw_payload:bytes())
				dec_payload = dec_packets[pkt_id]
			else
				dec_payload = dec_packets[pkt_id]
			end

			local tvb = dec_payload:tvb("Decrypted payload"):range()
			payload = tvb

			local proto_pkt_type = tvb(4,1):le_uint()
			if bit.band(proto_pkt_type, 0x80) == 0 and tvb:len() > 14 then -- response, AND there must be something to dissect here..
				local pkt_proto = bit.band(proto_pkt_type, bit.bnot(0x80))
				local pkt_method_id = bit.band(tvb(0xa, 4):le_uint(), bit.bnot(0x8000))
				local nex_data = tvb(14)
				local ticket_buff
				local buffer_len

				if proto_pkt_type == 10 then
					if pkt_method_id == 1 or pkt_method_id == 2 then -- 1: Login, 2: LoginEx
						buffer_len = nex_data(8, 4):le_uint()
						ticket_buff = nex_data(12, buffer_len)

						pid = nex_data(4, 4):le_uint()
						conn['pid'] = pid
						info = tostring(conn['pid'])
					elseif pkt_method_id == 3 then -- 3: RequestTicket
						buffer_len = nex_data(4, 4):le_uint()
						ticket_buff = nex_data(8, buffer_len)
						if conn['pid'] ~= nil then
							pid = conn['pid']
							info = tostring(conn['pid'])
						end
					end

					local ticket = ticket_buff(0, buffer_len-16)
					local hmac = ticket_buff(buffer_len-16, 16)

					local kerb_key = KERB_KEYS[pid]

					if kerb_key == nil then
						error("Kerberos key for PID " .. tostring(pid) .. " not found! Please add it (or the NEX password) to the config file.")
					end

					ticket = rc4.crypt(rc4.new_ks(kerb_key), ticket:bytes())
					secure_key = string.fromhex(tostring(ticket(0, 32)))

					if pkt_method_id == 1 or pkt_method_id == 2 then -- 1: Login, 2: LoginEx
						struct_header_len = 0
						has_struct_headers = false

						secure_url_len_off = 12 + struct_header_len + buffer_len
						secure_url_len = nex_data(secure_url_len_off, 2):le_uint()

						-- Time for a shitty heuristic!
						if 14 + secure_url_len > nex_data:len() then
							struct_header_len = 5
							has_struct_headers = true

							secure_url_len_off = 12 + struct_header_len + buffer_len

							secure_url_len = nex_data(secure_url_len_off, 2):le_uint()
						end
						conn['has_struct_headers'] = has_struct_headers
						conn['prudp_version'] = version

						secure_url_off = secure_url_len_off + 2
						secure_url = nex_data(secure_url_off, secure_url_len):string()

						addr = string.match(secure_url, "address=([^;]+)")
						port = string.match(secure_url, "port=([^;]+)")
						conn['secure_id'] = addr .. "-" .. port

						return_msg_len_off = secure_url_off + secure_url_len + 4 + 2 + 1
						if version == 1 then
							return_msg_len_off = return_msg_len_off + 8 -- skip date
						end

						return_msg_len = nex_data(return_msg_len_off, 2):le_uint()
						return_msg = nex_data(return_msg_len_off + 2, return_msg_len):string()

						major, minor, patch = return_msg:match("build:(%d+)_(%d+)_(%d+)")
						if major ~= nil then
							conn['nex_version'] = {tonumber(major), tonumber(minor), tonumber(patch)}
						end

						-- this packet is server->client, so we use the server ip (from the secure url) first, then the dst ip (client ip)
						new_conn_id = addr .. "-" .. port .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {
							[PORT_SERVER] = rc4.new_ks(secure_key),
							[PORT_CLIENT] = rc4.new_ks(secure_key),
							['nonsecure_pid'] = pid,
							['has_struct_headers'] = conn['has_struct_headers'],
							['prudp_version'] = conn['prudp_version'],
							['nex_version'] = conn['nex_version']
						}

						udp_table:add(tonumber(port), Dissector.get("nex"))
					elseif pkt_method_id == 3 then -- If we request a ticket seperately, use that secure key instead.
						new_conn_id = conn['secure_id'] .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {
							[PORT_SERVER] = rc4.new_ks(secure_key),
							[PORT_CLIENT] = rc4.new_ks(secure_key),
							['nonsecure_pid'] = pid,
							['has_struct_headers'] = conn['has_struct_headers'],
							['prudp_version'] = conn['prudp_version'],
							['nex_version'] = conn['nex_version']
						}
					end
				end
			end

			-- game detection
			if pkt_src == PORT_CLIENT and conn['game'] == nil and conn['nonsecure_pid'] ~= nil then
				for access_key, game_name in pairs(access_key_table) do
					if version == 0 then
						if pkt_signature:raw() == sig_v0(access_key, SECURE_KEYS[conn_id], pkt_seq, f_fragment_v0()(), raw_payload) then
							conn['game'] = game_name
							break
						end
					elseif version == 1 then
						-- for data..
						optional_data = "\x02\x01" .. string.char(f_fragment_v1()())
						if pkt_signature:raw() == sig_v1(access_key, buf:bytes(2+4, 8), SECURE_KEYS[conn_id], conn['server_conn_sig'], optional_data, raw_payload) then
							conn['game'] = game_name
							break
						end
					end
				end
				if conn['game'] == nil then
					conn['game'] = 'Unknown'
				end
			end
		end
	end

	if pkt_type ~= TYPE_DATA or pkt_flag_ack or pkt_flag_multi_ack then
		return
	end

	if payload == nil then
		return
	end

	local subtreeitem = tree:add(nex_proto, buf)
	subtreeitem:add(F.raw_payload, payload)

	local pkt_size = payload(0,4):le_uint()
	subtreeitem:add_le(F.size, payload(0,4))

	local pkt_proto_id = payload(4,1):le_uint()
	subtreeitem:add_le(F.proto, payload(4,1))

	local request = bit.band(pkt_proto_id, 0x80) ~= 0
	pkt_proto_id = bit.band(pkt_proto_id, bit.bnot(0x80))

	local info
	local conn, conn_id = find_connection(pinfo)

	if request then
		info = "Request"

		local pkt_call_id = payload(5,4):le_uint()
		subtreeitem:add_le(F.call_id, payload(5,4))

		local pkt_method_id = payload(9,4):le_uint()
		subtreeitem:add_le(F.method_id, payload(9,4))

		if payload:len() > 0xd then
			local tvb = payload(0xd)
			local t = subtreeitem:add(F.payload, tvb)

			
			dissect_req(conn, t, tvb, pkt_proto_id, pkt_method_id)
		end

		local proto_name, method_name = resolve(conn, pkt_proto_id, pkt_method_id)
		info = info .. string.format(" %s->%s, call=0x%08x", proto_name, method_name, pkt_call_id)
	else
		info = "Response"

		local pkt_success = payload(5,1):le_uint()
		if pkt_success == 1 then
			local pkt_call_id = payload(6,4):le_uint()
			subtreeitem:add_le(F.call_id, payload(6,4))
			local pkt_method_id = bit.band(payload(0xa, 4):le_uint(), bit.bnot(0x8000))
			subtreeitem:add_le(F.method_id, payload(0xa,4))

			if payload:len() > 0xe then
				local tvb = payload(0xe)
				local t = subtreeitem:add(F.payload, tvb)
				
				dissect_resp(conn, t, tvb, pkt_proto_id, pkt_method_id)
			end

			local proto_name, method_name = resolve(conn, pkt_proto_id, pkt_method_id)
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

Fraw = nexraw_proto.fields
_G["Fraw"] = Fraw -- apparently this isn't global enough >:(
_G["version_gt_eq"] = version_gt_eq
protos, nested_protos = dofile(script_path() .. "protos.inc")

Fraw.raw_payload = ProtoField.bytes("nex.rawpayload", "Decrypted PRUDP payload")

Fraw.size = ProtoField.uint32("nex.size", "Big ass size", base.HEX)
Fraw.proto = ProtoField.uint8("nex.proto", "Protocol", base.HEX, nil, 0x7f)
Fraw.call_id = ProtoField.uint32("nex.call_id", "Call ID", base.HEX)
Fraw.method_id = ProtoField.uint32("nex.method_id", "Method ID", base.HEX, nil, 0x7fff)
Fraw.payload = ProtoField.bytes("nex.payload", "Payload")

function nexraw_proto.dissector(buf, pinfo, tree)
	raw_payload = buf
	if pkt_type == TYPE_SYN and pkt_flag_ack then
		local partial_conn_id = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst)
		if CONNECTIONS[partial_conn_id] then
			CONNECTIONS[partial_conn_id]['server_conn_sig'] = pkt_conn_sig
		end
	end
	
	if pkt_type == TYPE_CONNECT and not pkt_flag_ack then
		-- This should be client->server. We knew the servers's IP and port, as well as the client's IP.
		local partial_conn_id = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src)
		local partial_conn = CONNECTIONS[partial_conn_id]
		local conn, conn_id = find_connection(pinfo)

		if SECURE_KEYS[partial_conn_id] ~= nil then
			if raw_payload then
				local first_buff_size = raw_payload(0, 4):le_uint() + 4
				local check_buffer_size = raw_payload(first_buff_size, 4):le_uint()
				local check_buffer = raw_payload(first_buff_size + 4, check_buffer_size)

				local check_contents = check_buffer(0, check_buffer:len() - 16)
				local check_hmac = check_buffer(check_buffer:len() - 16, 16)
				local secure_key = SECURE_KEYS[partial_conn_id]
				local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
				local pid = int_from_bytes(check_decrypted(0,4))
				if pid ~= partial_conn['nonsecure_pid'] then
					secure_key = secure_key:sub(1,16)
					local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
					local pid = int_from_bytes(check_decrypted(0,4))

					if pid ~= partial_conn['nonsecure_pid'] then
						print("Secure key is fucked!")
					end
				end

				CONNECTIONS[conn_id] = {
					[PORT_SERVER] = rc4.new_ks(secure_key),
					[PORT_CLIENT] = rc4.new_ks(secure_key),
					['nonsecure_pid'] = partial_conn['nonsecure_pid'],
					['has_struct_headers'] = partial_conn['has_struct_headers'],
					['prudp_version'] = partial_conn['prudp_version'],
					['nex_version'] = partial_conn['nex_version'],
					['server_conn_sig'] = partial_conn['server_conn_sig'],
					['client_conn_sig'] = pkt_conn_sig,
				}
				SECURE_KEYS[conn_id] = secure_key
				CONNECTIONS[partial_conn_id] = nil
				SECURE_KEYS[partial_conn_id] = nil
			else
				print("Secure connection CONNECT without payload?")
				CONNECTIONS[conn_id] = {
					[PORT_SERVER] = rc4.new_ks("CD&ML"),
					[PORT_CLIENT] = rc4.new_ks("CD&ML"),
					['nonsecure_pid'] = partial_conn['nonsecure_pid'],
					['has_struct_headers'] = partial_conn['has_struct_headers'],
					['prudp_version'] = partial_conn['prudp_version'],
					['nex_version'] = partial_conn['nex_version'],
					['server_conn_sig'] = partial_conn['server_conn_sig'],
					['client_conn_sig'] = pkt_conn_sig,
				}
				SECURE_KEYS[conn_id] = secure_key
				CONNECTIONS[partial_conn_id] = nil
				SECURE_KEYS[partial_conn_id] = nil
			end
		else
			set_connection(pinfo, {
					[PORT_SERVER] = rc4.new_ks("CD&ML"),
					[PORT_CLIENT] = rc4.new_ks("CD&ML"),
					['client_conn_sig'] = pkt_conn_sig,
				})
		end
	end
	if pkt_type == TYPE_CONNECT and pkt_flag_ack and pkt_src ~= PORT_SERVER then
		-- This should be server->client connection ack, but with a mismatched pkt_src. Fix up the keys
		conn, conn_id = find_connection(pinfo)
		conn[pkt_src] = conn[PORT_SERVER]
		print("Mismatched server pkt_src " .. pkt_src .. ", correcting key...")
	end

	pkt_type = TYPE_DATA
	if pkt_type == TYPE_DATA and not pkt_flag_ack and not pkt_flag_multi_ack then
		if raw_payload then
			local conn
			local conn_id

			conn, conn_id = find_connection(pinfo)

			-- I hate this. Please come up with a better method.
			pkt_id = pinfo.number
			if dec_packets[pkt_id] == nil then
				dec_packets[pkt_id] = raw_payload:bytes()
				dec_payload = dec_packets[pkt_id]
			else
				dec_payload = dec_packets[pkt_id]
			end

			local tvb = dec_payload:tvb("Decrypted payload"):range()
			payload = tvb

			local proto_pkt_type = tvb(4,1):le_uint()
			if bit.band(proto_pkt_type, 0x80) == 0 and tvb:len() > 14 then -- response, AND there must be something to dissect here..
				local pkt_proto = bit.band(proto_pkt_type, bit.bnot(0x80))
				local pkt_method_id = bit.band(tvb(0xa, 4):le_uint(), bit.bnot(0x8000))
				local nex_data = tvb(14)
				local ticket_buff
				local buffer_len

				if proto_pkt_type == 10 then
					if pkt_method_id == 1 or pkt_method_id == 2 then -- 1: Login, 2: LoginEx
						buffer_len = nex_data(8, 4):le_uint()
						ticket_buff = nex_data(12, buffer_len)

						pid = nex_data(4, 4):le_uint()
						conn['pid'] = pid
						info = tostring(conn['pid'])
					elseif pkt_method_id == 3 then -- 3: RequestTicket
						buffer_len = nex_data(4, 4):le_uint()
						ticket_buff = nex_data(8, buffer_len)
						if conn['pid'] ~= nil then
							pid = conn['pid']
							info = tostring(conn['pid'])
						end
					end

					local ticket = ticket_buff(0, buffer_len-16)
					local hmac = ticket_buff(buffer_len-16, 16)

					local kerb_key = KERB_KEYS[pid]

					if kerb_key == nil then
						error("Kerberos key for PID " .. tostring(pid) .. " not found! Please add it (or the NEX password) to the config file.")
					end

					ticket = rc4.crypt(rc4.new_ks(kerb_key), ticket:bytes())
					secure_key = string.fromhex(tostring(ticket(0, 32)))

					if pkt_method_id == 1 or pkt_method_id == 2 then -- 1: Login, 2: LoginEx
						struct_header_len = 0
						has_struct_headers = false

						secure_url_len_off = 12 + struct_header_len + buffer_len
						secure_url_len = nex_data(secure_url_len_off, 2):le_uint()

						-- Time for a shitty heuristic!
						if 14 + secure_url_len > nex_data:len() then
							struct_header_len = 5
							has_struct_headers = true

							secure_url_len_off = 12 + struct_header_len + buffer_len

							secure_url_len = nex_data(secure_url_len_off, 2):le_uint()
						end
						conn['has_struct_headers'] = has_struct_headers
						conn['prudp_version'] = version

						secure_url_off = secure_url_len_off + 2
						secure_url = nex_data(secure_url_off, secure_url_len):string()

						addr = string.match(secure_url, "address=([^;]+)")
						port = string.match(secure_url, "port=([^;]+)")
						conn['secure_id'] = addr .. "-" .. port

						return_msg_len_off = secure_url_off + secure_url_len + 4 + 2 + 1
						if version == 1 then
							return_msg_len_off = return_msg_len_off + 8 -- skip date
						end

						return_msg_len = nex_data(return_msg_len_off, 2):le_uint()
						return_msg = nex_data(return_msg_len_off + 2, return_msg_len):string()

						major, minor, patch = return_msg:match("build:(%d+)_(%d+)_(%d+)")
						if major ~= nil then
							conn['nex_version'] = {tonumber(major), tonumber(minor), tonumber(patch)}
						end

						-- this packet is server->client, so we use the server ip (from the secure url) first, then the dst ip (client ip)
						new_conn_id = addr .. "-" .. port .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {
							[PORT_SERVER] = rc4.new_ks(secure_key),
							[PORT_CLIENT] = rc4.new_ks(secure_key),
							['nonsecure_pid'] = pid,
							['has_struct_headers'] = conn['has_struct_headers'],
							['prudp_version'] = conn['prudp_version'],
							['nex_version'] = conn['nex_version']
						}

						udp_table:add(tonumber(port), Dissector.get("nex"))
					elseif pkt_method_id == 3 then -- If we request a ticket seperately, use that secure key instead.
						new_conn_id = conn['secure_id'] .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {
							[PORT_SERVER] = rc4.new_ks(secure_key),
							[PORT_CLIENT] = rc4.new_ks(secure_key),
							['nonsecure_pid'] = pid,
							['has_struct_headers'] = conn['has_struct_headers'],
							['prudp_version'] = conn['prudp_version'],
							['nex_version'] = conn['nex_version']
						}
					end
				end
			end

			-- game detection
			if pkt_src == PORT_CLIENT and conn['game'] == nil and conn['nonsecure_pid'] ~= nil then
				for access_key, game_name in pairs(access_key_table) do
					if version == 0 then
						if pkt_signature:raw() == sig_v0(access_key, SECURE_KEYS[conn_id], pkt_seq, f_fragment_v0()(), raw_payload) then
							conn['game'] = game_name
							break
						end
					elseif version == 1 then
						-- for data..
						optional_data = "\x02\x01" .. string.char(f_fragment_v1()())
						if pkt_signature:raw() == sig_v1(access_key, buf:bytes(2+4, 8), SECURE_KEYS[conn_id], conn['server_conn_sig'], optional_data, raw_payload) then
							conn['game'] = game_name
							break
						end
					end
				end
				if conn['game'] == nil then
					conn['game'] = 'Unknown'
				end
			end
		end
	end

	if pkt_type ~= TYPE_DATA or pkt_flag_ack or pkt_flag_multi_ack then
		return
	end

	if payload == nil then
		return
	end

	local subtreeitem = tree:add(nexraw_proto, buf)
	subtreeitem:add(Fraw.raw_payload, payload)

	local pkt_size = payload(0,4):le_uint()
	subtreeitem:add_le(Fraw.size, payload(0,4))

	local pkt_proto_id = payload(4,1):le_uint()
	subtreeitem:add_le(Fraw.proto, payload(4,1))

	local request = bit.band(pkt_proto_id, 0x80) ~= 0
	pkt_proto_id = bit.band(pkt_proto_id, bit.bnot(0x80))

	local info
	local conn, conn_id = find_connection(pinfo)

	if request then
		info = "Request"

		local pkt_call_id = payload(5,4):le_uint()
		subtreeitem:add_le(Fraw.call_id, payload(5,4))

		local pkt_method_id = payload(9,4):le_uint()
		subtreeitem:add_le(Fraw.method_id, payload(9,4))

		if payload:len() > 0xd then
			local tvb = payload(0xd)
			local t = subtreeitem:add(Fraw.payload, tvb)

			
			dissect_req(conn, t, tvb, pkt_proto_id, pkt_method_id)
		end

		local proto_name, method_name = resolve(conn, pkt_proto_id, pkt_method_id)
		info = info .. string.format(" %s->%s, call=0x%08x", proto_name, method_name, pkt_call_id)
	else
		info = "Response"

		local pkt_success = payload(5,1):le_uint()
		if pkt_success == 1 then
			local pkt_call_id = payload(6,4):le_uint()
			subtreeitem:add_le(Fraw.call_id, payload(6,4))
			local pkt_method_id = bit.band(payload(0xa, 4):le_uint(), bit.bnot(0x8000))
			subtreeitem:add_le(Fraw.method_id, payload(0xa,4))

			if payload:len() > 0xe then
				local tvb = payload(0xe)
				local t = subtreeitem:add(Fraw.payload, tvb)
				
				dissect_resp(conn, t, tvb, pkt_proto_id, pkt_method_id)
			end

			local proto_name, method_name = resolve(conn, pkt_proto_id, pkt_method_id)
			info = info .. string.format(" Success %s->%s call=%08x", proto_name, method_name, pkt_call_id)
		else
			local pkt_err = payload(6,4):le_uint()
			local pkt_call_id = payload(0xa, 4):le_uint()
			subtreeitem:add_le(Fraw.call_id, payload(0xa,4))

			info = info .. string.format(" Failure, err=%08x, call=0x%08x", pkt_err, pkt_call_id)
		end
	end

	pinfo.cols.info = "NEX " .. info
end

udp_table = DissectorTable.get("udp.port")
-- prudpv0
udp_table:add(60000, nex_proto)
-- prudpv1
udp_table:add(59900, nex_proto)

tcp_table = DissectorTable.get("tcp.port")
-- raw NEX
tcp_table:add(1, nexraw_proto)
