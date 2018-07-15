rc4 = require("rc4")
md5 = require("md5")

local prudp_v0_proto = Proto("prudp", "PRUDP")

local ports = {
	[0xa1] = "Server",
	[0xaf] = "Client"
}

local pkt_types = {
	[0] = "SYN",
	[1] = "CONNECT",
	[2] = "DATA",
	[3] = "DISCONNECT",
	[4] = "PING"
}

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
	for i=1, a do
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
	for i=0,bytearr:len()-1 do
		out = bit.bor(out, bit.lshift(bytearr:get_index(i), i*8))
	end
	return out
end

local KERB_KEYS = {}
KERB_KEYS[1863211397] = gen_kerb_key(1863211397, "|+GF-i):/7Z87_:q")
KERB_KEYS[1847701639] = gen_kerb_key(1847701639, "ORbL78Oo>Y]-^(MF")

local SECURE_KEYS = {}
local CONNECTIONS = {}
local dec_packets = {}

local F = prudp_v0_proto.fields
F.src = ProtoField.uint8("prudp.src", "Source", base.HEX, ports)
F.dst = ProtoField.uint8("prudp.dst", "Destination", base.HEX, ports)
F.type = ProtoField.uint16("prudp.type", "Type", base.HEX, pkt_types, 0xf)
F.flag_ack = ProtoField.bool("prudp.ack", "Ack", base.HEX, nil, 0x10)
F.flag_reliable = ProtoField.bool("prudp.reliable", "Reliable", base.HEX, nil, 0x20)
F.flag_need_ack = ProtoField.bool("prudp.need_ack", "Need ack", base.HEX, nil, 0x40)
F.flag_has_size = ProtoField.bool("prudp.has_size", "Has size", base.HEX, nil, 0x80)
F.flag_multi_ack = ProtoField.bool("prudp.multi_ack", "Multi ack", base.HEX, nil, 0x2000)

F.session_id = ProtoField.uint8("prudp.session", "Session", base.HEX)
F.packet_sig = ProtoField.uint32("prudp.packet_sig", "Packet signature", base.HEX)
F.seq = ProtoField.uint16("prudp.seq", "Sequence number", base.HEX)

F.conn_sig = ProtoField.uint32("prudp.conn_sig", "Connection signature", base.HEX)
F.frag = ProtoField.uint8("prudp.frag", "Fragment", base.HEX)
F.size = ProtoField.uint16("prudp.size", "Packet size", base.HEX)

F.payload = ProtoField.bytes("prudp.payload", "Payload")
F.checksum = ProtoField.uint8("prudp.checksum", "Checksum", base.HEX)

function prudp_v0_proto.dissector(buf,pinfo,tree)
	pinfo.cols.protocol = "PRUDP"
	-- Parse the packet header.

	local subtree = tree:add(prudp_v0_proto, buf(), "PRUDP")
	
	local payload_size = nil

	local pkt_src = buf(0,1):le_uint()
	subtree:add(F.src, buf(0,1))

	local pkt_dst = buf(1,1):le_uint()
	subtree:add(F.dst, buf(1,1))
	
	local pkt_op_flags = buf(2,2):le_uint()

	local pkt_type = bit.band(pkt_op_flags, 0xf)
	subtree:add_le(F.type, buf(2,2))

	local flags = subtree:add(prudp_v0_proto, buf(), "Flags")

	local pkt_flag_ack = bit.band(pkt_op_flags, 0x10) ~= 0
	flags:add_le(F.flag_ack, buf(2,2))
	local pkt_flag_reliable = bit.band(pkt_op_flags, 0x20) ~= 0
	flags:add_le(F.flag_reliable, buf(2,2))
	local pkt_flag_need_ack = bit.band(pkt_op_flags, 0x40) ~= 0
	flags:add_le(F.flag_need_ack, buf(2,2))
	local pkt_flag_has_size = bit.band(pkt_op_flags, 0x80) ~= 0
	flags:add_le(F.flag_has_size, buf(2,2))
	local pkt_flag_multi_ack = bit.band(pkt_op_flags, 0x2000) ~= 0
	flags:add_le(F.flag_multi_ack, buf(2,2))

	subtree:add(F.session_id, buf(4,1))
	subtree:add_le(F.packet_sig, buf(5,4))

	local pkt_seq = buf(9,2):le_uint()
	subtree:add_le(F.seq, buf(9, 2))

	-- Packet specific.
	off = 11
	if pkt_type == 0 or pkt_type == 1 then
		subtree:add_le(F.conn_sig, buf(11, 4))
		off = off + 4
	elseif pkt_type == 2 then
		subtree:add_le(F.frag, buf(11, 1))
		off = off + 1
	end

	if pkt_flag_has_size then
		payload_size = buf(off, 2):le_uint()
		subtree:add_le(F.size, buf(off, 2))
		off = off + 2
	end

	local info = pkt_types[pkt_type]
	
	if pkt_type == 0 and pkt_src == 0xaf and pkt_dst == 0xa1 then
		a = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src)
		if CONNECTIONS[a] == nil then
			CONNECTIONS[a] = {[0xa1]=rc4.new_ks("CD&ML"), [0xaf]=rc4.new_ks("CD&ML")}
		end
	end

	if pkt_type == 1 and not pkt_flag_ack then
		local payload = buf(off, buf:len() - off - 1):bytes()
		local conn
		local conn_id

		a = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst)
		b = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src)
		if CONNECTIONS[a] ~= nil then
			conn = CONNECTIONS[a]
			conn_id = a
		elseif CONNECTIONS[b] ~= nil then
			conn = CONNECTIONS[b]
			conn_id = b
		end
		if SECURE_KEYS[conn_id] ~= nil then
			if buf:len() > 15 then 
				local payload = buf(15, buf:len() - 16)
				subtree:add(F.payload, payload)
				local first_buff_size = payload(0, 4):le_uint() + 4
				local check_buffer_size = payload(first_buff_size, 4):le_uint()
				local check_buffer = payload(first_buff_size + 4, check_buffer_size)

				local check_contents = check_buffer(0, check_buffer:len() - 16)
				local check_hmac = check_buffer(check_buffer:len() - 16, 16)

				local secure_key = SECURE_KEYS[conn_id]
				local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
				local pid = int_from_bytes(check_decrypted(0,4))
				if pid ~= conn['nonsecure_pid'] then
					secure_key = secure_key:sub(1,16)
					local check_decrypted = rc4.crypt(rc4.new_ks(secure_key), check_contents:bytes())
					local pid = int_from_bytes(check_decrypted(0,4))
					if pid ~= conn['nonsecure_pid'] then
						info = "Secure key is fucked!"
					else
						CONNECTIONS[conn_id] = { [0xa1]=rc4.new_ks(secure_key), [0xaf]=rc4.new_ks(secure_key), ['nonsecure_pid'] = conn['nonsecure_pid'] }
						SECURE_KEYS[conn_id] = secure_key
					end
				end
			end
		end
	end

	if pkt_type == 2 and not pkt_flag_ack then
		if payload_size ~= 0 then
			local enc_payload = buf(off, buf:len() - off - 1):bytes()
			local conn
			local conn_id

			a = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst)
			b = tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .. "-" .. tostring(pinfo.src)

			if CONNECTIONS[a] ~= nil then
				conn = CONNECTIONS[a]
				conn_id = a
			elseif CONNECTIONS[b] ~= nil then
				conn = CONNECTIONS[b]
				conn_id = b
			end

			pkt_id = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port) .."-".. tostring(pkt_seq)
			if dec_packets[pkt_id] == nil then
				dec_packets[pkt_id] = rc4.crypt(conn[pkt_src], enc_payload)
				dec_payload = dec_packets[pkt_id]
			else
				dec_payload = dec_packets[pkt_id]
			end

			tvb = dec_payload:tvb("Decrypted payload"):range()
			subtree:add(F.payload, tvb)
			
			local proto_pkt_type = tvb(4,1):le_uint()
			if bit.band(proto_pkt_type, 0x80) == 0 and tvb:len() > 14 then -- response, AND there must be something to dissect here..
				local pkt_proto = bit.band(proto_pkt_type, bit.bnot(0x80))
				local pkt_method_id = bit.band(tvb(0xa, 4):le_uint(), bit.bnot(0x8000))
				local nex_data = tvb(14)
				local ticket_buff
				local buffer_len

				if proto_pkt_type == 10 then
					if pkt_method_id == 1 or pkt_method_id == 2 then
						buffer_len = nex_data(8, 4):le_uint()
						ticket_buff = nex_data(12, buffer_len)

						pid = nex_data(4, 4):le_uint()
						conn['pid'] = pid
						info = tostring(conn['pid'])
					elseif pkt_method_id == 3 then
						buffer_len = nex_data(4, 4):le_uint()
						ticket_buff = nex_data(8, buffer_len)
						if conn['pid'] ~= nil then
							pid = conn['pid']
							info = tostring(conn['pid'])
						end
					end

					ticket = ticket_buff(0, buffer_len-16)
					hmac = ticket_buff(buffer_len-16, 16)

					kerb_key = KERB_KEYS[pid]
					ticket = rc4.crypt(rc4.new_ks(kerb_key), ticket:bytes())
					secure_key = string.fromhex(tostring(ticket(0, 32)))

					if pkt_method_id == 1 or pkt_method_id == 2 then
						secure_url_len = nex_data(12 + buffer_len, 2):le_uint()
						secure_url = nex_data(14 + buffer_len, secure_url_len):string()
						addr = string.match(secure_url, "address=([^;]+)")
						port = string.match(secure_url, "port=([^;]+)")
						conn['secure_id'] = addr .. "-" .. port

						-- this packet is server->client, so we use the server ip (from the secure url) first, then the dst ip (client ip)
						new_conn_id = addr .. "-" .. port .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {[0xa1]=rc4.new_ks(secure_key), [0xaf]=rc4.new_ks(secure_key), ['nonsecure_pid'] = pid}

						nex_proto = udp_table:get_dissector(60000)
						udp_table:add(tonumber(port), nex_proto)
					elseif pkt_method_id == 3 then -- If we request a ticket seperately, use that secure key instead.
						new_conn_id = conn['secure_id'] .. "-" .. tostring(pinfo.dst)
						SECURE_KEYS[new_conn_id] = secure_key
						CONNECTIONS[new_conn_id] = {[0xa1]=rc4.new_ks(secure_key), [0xaf]=rc4.new_ks(secure_key), ['nonsecure_pid'] = pid}
					end
				end
			end
			
			payload_size = buf:len() - off - 1
			off = buf:len()-1
		end
	end

	subtree:add(F.checksum, buf(off, 1))

	if pkt_flag_ack then
		info = info .. " ACK"
	elseif pkt_flag_reliable then
		info = info .. " RELIABLE"
	elseif pkt_flag_need_ack then
		info = info .. " NEED_ACK"
	elseif pkt_flag_has_size then
		info = info .. " HAS_SIZE"
	elseif pkt_flag_multi_ack ~= 0 then
		info = info .. " MULTI_ACK"
	end
	
	if payload_size ~= nil and payload_size ~= 0 then
		info = info .. " " .. tostring(payload_size) .. " bytes data"
	end

	pinfo.cols.info = info
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(60000, prudp_v0_proto)