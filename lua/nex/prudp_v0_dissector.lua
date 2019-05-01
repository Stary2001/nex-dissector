require("common")

local prudp_v0_proto = Proto("prudpv0", "PRUDPv0")

local F = prudp_v0_proto.fields
F.src = ProtoField.uint8("prudpv0.src", "Source", base.HEX, ports)
F.dst = ProtoField.uint8("prudpv0.dst", "Destination", base.HEX, ports)
F.type = ProtoField.uint16("prudpv0.type", "Type", base.HEX, pkt_types, 0xf)
F.flag_ack = ProtoField.bool("prudpv0.ack", "Ack", base.HEX, nil, 0x10)
F.flag_reliable = ProtoField.bool("prudpv0.reliable", "Reliable", base.HEX, nil, 0x20)
F.flag_need_ack = ProtoField.bool("prudpv0.need_ack", "Need ack", base.HEX, nil, 0x40)
F.flag_has_size = ProtoField.bool("prudpv0.has_size", "Has size", base.HEX, nil, 0x80)
F.flag_multi_ack = ProtoField.bool("prudpv0.multi_ack", "Multi ack", base.HEX, nil, 0x2000)

F.session_id = ProtoField.uint8("prudpv0.session", "Session", base.HEX)
F.packet_sig = ProtoField.uint32("prudpv0.packet_sig", "Packet signature", base.HEX)
F.seq = ProtoField.uint16("prudpv0.seq", "Sequence number", base.HEX)

F.conn_sig = ProtoField.uint32("prudpv0.conn_sig", "Connection signature", base.HEX)
F.frag = ProtoField.uint8("prudpv0.frag", "Fragment", base.HEX)
F.size = ProtoField.uint16("prudpv0.size", "Packet size", base.HEX)

F.payload = ProtoField.bytes("prudpv0.payload", "Payload")
F.checksum = ProtoField.uint8("prudpv0.checksum", "Checksum", base.HEX)

function prudp_v0_proto.dissector(buf,pinfo,tree)
	pinfo.cols.protocol = "PRUDP v0"
	-- Parse the packet header.

	local subtree = tree:add(prudp_v0_proto, buf(), "PRUDP v0")
	
	local payload_size = nil

	local pkt = {}

	pkt.src = buf(0,1):le_uint()
	subtree:add(F.src, buf(0,1))

	pkt.dst = buf(1,1):le_uint()
	subtree:add(F.dst, buf(1,1))
	
	local pkt_op_flags = buf(2,2):le_uint()

	pkt.type = bit.band(pkt_op_flags, 0xf)
	subtree:add_le(F.type, buf(2,2))

	local flags = subtree:add(prudp_v0_proto, buf(2,2), "Flags")

	pkt.flags = {}
	pkt.flags.ack = bit.band(pkt_op_flags, 0x10) ~= 0
	flags:add_le(F.flag_ack, buf(2,2))
	pkt.flags.reliable = bit.band(pkt_op_flags, 0x20) ~= 0
	flags:add_le(F.flag_reliable, buf(2,2))
	pkt.flags.need_ack = bit.band(pkt_op_flags, 0x40) ~= 0
	flags:add_le(F.flag_need_ack, buf(2,2))
	pkt.flags.has_size = bit.band(pkt_op_flags, 0x80) ~= 0
	flags:add_le(F.flag_has_size, buf(2,2))
	pkt.flags.multi_ack = bit.band(pkt_op_flags, 0x2000) ~= 0
	flags:add_le(F.flag_multi_ack, buf(2,2))

	pkt.session_id = buf(4,1):le_uint()
	subtree:add(F.session_id, buf(4,1))
	subtree:add_le(F.packet_sig, buf(5,4))

	pkt.seq = buf(9,2):le_uint()
	subtree:add_le(F.seq, buf(9, 2))

	-- we're done with the general header now.
	-- parse the packet specific data:

	off = 11
	if pkt.type == 0 or pkt.type == 1 then -- ACKs and CONNECTs have a connection signature.
		subtree:add_le(F.conn_sig, buf(11, 4))
		off = off + 4
	elseif pkt.type == 2 then -- DATA packets have a fragment.
		subtree:add_le(F.frag, buf(11, 1))
		off = off + 1
	end

	local payload_size
	if pkt.flags.has_size then -- Anything with the 'has size' flag set has one.
		payload_size = buf(off, 2):le_uint()
		subtree:add_le(F.size, buf(off, 2))
		off = off + 2
	elseif pkt.type == 1 or pkt.type == 2 then
		payload_size = buf:len() - off - 1
	end

	if payload_size and payload_size ~= 0 then
		subtree:add(F.payload, buf:range(off, payload_size))
		off = off + payload_size
	end

	local info = pkt_types[pkt.type]
	subtree:add(F.checksum, buf(off, 1))

	if pkt.flags.ack then
		info = info .. " ACK"
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
	if pkt.flags.multi_ack then
		info = info .. " MULTI_ACK"
	end
	
	if payload_size ~= nil and payload_size ~= 0 then
		info = info .. " " .. tostring(payload_size) .. " bytes data"
	end

	pinfo.cols.info = info
end