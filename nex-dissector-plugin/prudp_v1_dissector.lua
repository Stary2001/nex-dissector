if not PROTO_V1 then
	_G["PROTO_V1"] = true

require("common")

-- See: https://github.com/Kinnay/NintendoClients/wiki/PRUDP-Protocol

local prudp_v1_proto = Proto("prudpv1", "PRUDPv1")

local F = prudp_v1_proto.fields
F.magic = ProtoField.uint8("prudpv1.magic", "Magic", base.HEX)
F.version = ProtoField.uint8("prudpv1.version", "Version", base.HEX)
F.extra_data_length = ProtoField.uint8("prudpv1.extra_data_size", "Packet-specific data size", base.HEX)
F.payload_size = ProtoField.uint8("prudpv1.payload_size", "Payload size", base.HEX)

F.packet_sig = ProtoField.bytes("prudpv1.packet_sig", "Packet signature")

F.src = ProtoField.uint8("prudpv1.src", "Source", base.HEX, ports)
F.dst = ProtoField.uint8("prudpv1.dst", "Destination", base.HEX, ports)
F.type = ProtoField.uint16("prudpv1.type", "Type", base.HEX, pkt_types, 0xf)

F.flag_ack = ProtoField.bool("prudpv1.ack", "Ack", base.HEX, nil, 0x10)
F.flag_reliable = ProtoField.bool("prudpv1.reliable", "Reliable", base.HEX, nil, 0x20)
F.flag_need_ack = ProtoField.bool("prudpv1.need_ack", "Need ack", base.HEX, nil, 0x40)
F.flag_has_size = ProtoField.bool("prudpv1.has_size", "Has size", base.HEX, nil, 0x80)
F.flag_multi_ack = ProtoField.bool("prudpv1.multi_ack", "Multi ack", base.HEX, nil, 0x2000)

F.session_id = ProtoField.uint8("prudpv1.session", "Session", base.HEX)
F.multi_ack_version = ProtoField.uint8("prudpv1.multi_ack_version", "Multi ack version", base.HEX)
F.seq = ProtoField.uint16("prudpv1.seq", "Sequence number", base.HEX)

F.payload = ProtoField.bytes("prudpv1.payload", "Payload")
F.defragmented_payload = ProtoField.bytes("prudpv1.defragmented_payload", "Defragmented payload")

F.option_id = ProtoField.uint8("prudpv1.option_id", "Option id", base.HEX)
F.option_size = ProtoField.uint8("prudpv1.option_size", "Option size", base.HEX)
F.option_bytes = ProtoField.bytes("prudpv1.option_bytes", "Option bytes")
F.supported_functions = ProtoField.bytes("prudpv1.supported_functions", "Supported functions")
F.connection_signature = ProtoField.bytes("prudpv1.connection_signature", "Connection signature")
F.fragment = ProtoField.uint8("prudpv1.fragment", "Fragment")

function prudp_v1_proto.dissector(buf,pinfo,tree)
	pinfo.cols.protocol = "PRUDP v1"
	-- Parse the packet header.

	local subtree = tree:add(prudp_v1_proto, buf(), "PRUDP v1")

	local pkt = {}

	subtree:add(F.magic, buf(0,2))
	subtree:add(F.version, buf(2,1))

	local extra_data_length = buf(3,1):le_uint()
	subtree:add_le(F.extra_data_length, buf(3,1))

	local payload_size = buf(4,2):le_uint()
	subtree:add_le(F.payload_size, buf(4,2))

	pkt.src = buf(6,1):le_uint()
	subtree:add(F.src, buf(6,1))

	pkt.dst = buf(7,1):le_uint()
	subtree:add(F.dst, buf(7,1))

	local pkt_op_flags = buf(8,2):le_uint()

	pkt.type = bit.band(pkt_op_flags, 0xf)
	subtree:add_le(F.type, buf(8,2))

	local flags = subtree:add(prudp_v1_proto, buf(8,2), "Flags")

	pkt.flags = {}
	pkt.flags.ack = bit.band(pkt_op_flags, 0x10) ~= 0
	flags:add_le(F.flag_ack, buf(8,2))
	pkt.flags.reliable = bit.band(pkt_op_flags, 0x20) ~= 0
	flags:add_le(F.flag_reliable, buf(8,2))
	pkt.flags.need_ack = bit.band(pkt_op_flags, 0x40) ~= 0
	flags:add_le(F.flag_need_ack, buf(8,2))
	pkt.flags.has_size = bit.band(pkt_op_flags, 0x80) ~= 0
	flags:add_le(F.flag_has_size, buf(8,2))
	pkt.flags.multi_ack = bit.band(pkt_op_flags, 0x2000) ~= 0
	flags:add_le(F.flag_multi_ack, buf(8,2))

	pkt.session = buf(10, 1):le_uint()
	subtree:add_le(F.session_id, buf(10, 1))
	subtree:add_le(F.multi_ack_version, buf(11, 1))
	pkt.multi_ack_version = buf(11, 1):le_uint()

	pkt.seq = buf(12,2):le_uint()
	subtree:add_le(F.seq, buf(12, 2))
	subtree:add_le(F.packet_sig, buf(14,16))

	local off = 2 + 12 + 16
	if extra_data_length > 0 then
		local options = subtree:add(prudp_v1_proto, buf(off, extra_data_length), "Options")
		local orig = off
		while off < orig+extra_data_length do
			local opt_id = buf(off, 1):le_uint()
			local opt_size = buf(off+1, 1):le_uint()

			local opt = options:add(prudp_v1_proto, buf(off, opt_size+2)):set_text("Option")
			opt:add(F.option_id, buf(off, 1))
			opt:add(F.option_size, buf(off+1, 1))

			local option_bytes = buf(off + 2, opt_size)

			if opt_id == 0 then
				opt:add(F.supported_functions, option_bytes)
			elseif opt_id == 1 then
				opt:add(F.connection_signature, option_bytes)
			elseif opt_id == 2 then
				pkt.fragment = option_bytes:le_uint()
				opt:add(F.fragment, option_bytes)
			else
				opt:add(F.option_bytes, option_bytes)
			end

			off = off + 2 + opt_size
		end
	end

	if payload_size and payload_size ~= 0 then
		local payload_range = buf:range(off, payload_size)
		subtree:add(F.payload, payload_range)

		defragment(1, subtree, pkt, pinfo, payload_range, F.defragmented_payload)
	end

	local info = pkt_types[pkt.type]

	if pkt.flags.ack then
		info = info .. " ACK"
	end
	if pkt.flags.multi_ack then
		info = info .. " MULTI_ACK"
	end
	if pkt.fragment ~= nil then
		info = info .. " FRAGMENT " .. tostring(pkt.fragment)
	end
	if pkt.session ~= nil then
		info = info .. " SESSION " .. string.format("0x%02x", pkt.session)
	end
	if pkt.flags.reliable then
		info = info .. " RELIABLE"
	end
	if pkt.flags.need_ack then
		info = info .. " NEED_ACK"
	end
	if pkt.flags.has_size then
		info = info .. " HAS_SIZE"
	end

	if payload_size ~= nil and payload_size ~= 0 then
		info = info .. " " .. tostring(payload_size) .. " bytes data"
		if pkt.defragmented_size ~= nil then
			info = info .. " DEFRAGMENTED_SIZE " .. tostring(pkt.defragmented_size)
		end
	end

	pinfo.cols.info = info
end

--udp_table = DissectorTable.get("udp.port")
--udp_table:add(59900, prudp_v1_proto)
--udp_table:add(59911, prudp_v1_proto)
end