local nex_proto = Proto("nex", "NEX")
local prudp_proto

function proto_buffer(tree, stream)
	length = stream['data'](0,4):le_uint()
	buffer = stream['data'](0, length)
	stream['data'] = stream['data'](length)
	local sub = tree:add(ProtoField.uint32(stream['name'] .. "_length", "Length", base.HEX), length)
	data = ProtoField.bytes(stream['name'] .. "_data", "Data")
	sub:add(data, buffer)
end

local protos = require("protos")

local F = nex_proto.fields
F.size = ProtoField.uint32("nex.size", "Big ass size", base.HEX)
F.proto = ProtoField.uint8("nex.proto", "Protocol", base.HEX, nil, 0x7f)
F.call_id = ProtoField.uint32("nex.call_id", "Call ID", base.HEX)
F.method_id = ProtoField.uint32("nex.method_id", "Method ID", base.HEX, nil, 0x7fff)
F.payload = ProtoField.bytes("nex.payload", "Payload")

local f_type = Field.new("prudp.type")
local f_payload = Field.new("prudp.payload")
local f_ack = Field.new("prudp.ack")

function resolve(proto_id, method_id)
	local proto_name, method_name
	proto = protos[proto_id]
	if proto ~= nil then
		proto_name = proto['name']
		if proto['methods'][method_id] ~= nil then
			method_name = proto['methods'][method_id]['name']
		else
			method_name = "Unknown_"..string.format("0x%04x", method_id)
		end
	else
		proto_name = string.format("0x%02x", proto_id)
		method_name = string.format("0x%04x", method_id)
	end
	return proto_name, method_name
end

function dissect_req(tree, tvb, proto, method)
	if protos[proto] ~= nil then
		p = protos[proto]
		if p['methods'][method_id] ~= nil and p['methods'][method_id]['req'] ~= nil then
			p['methods'][method_id]['req'](tree, tvb)
		end
	end
end

function dissect_resp(tree, tvb, proto, method)
	if protos[proto] ~= nil then
		p = protos[proto]
		if p['methods'][method_id] ~= nil and p['methods'][method_id]['resp'] ~= nil then
			p['methods'][method_id]['req'](tree, tvb)
		end
	end
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
		
		local tvb = payload(0xd)
		local t = subtreeitem:add(F.payload, tvb)
		dissect_req(t, tvb, pkt_proto_id, pkt_method_id)

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

			local tvb = payload(0xe)
			local t = subtreeitem:add(F.payload, tvb)
			dissect_resp(t, tvb, pkt_proto_id, pkt_method_id)

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