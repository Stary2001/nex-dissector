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

local fragments_v1 = {}
local sequence_stream = {}
local first_sequence = {}
local deferred_fragments = {}

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

		if pkt.type == TYPE_DATA then
			local base_id = tostring(pinfo.src) .. "-" .. tostring(pinfo.src_port) .. "-" .. tostring(pinfo.dst) .. "-" .. tostring(pinfo.dst_port)
			if first_sequence[base_id] == nil then
				first_sequence[base_id] = pkt.seq
			end
			local function make_sequence_id(seq)
				return base_id .. "+" .. tostring(pkt.src) .. "-" .. tostring(pkt.dst) .. "-" .. tostring(pkt.session) .. "-" .. tostring(seq)
			end
			local payload = payload_range:bytes()
			local sequence_id = make_sequence_id(pkt.seq)
			sequence_stream[sequence_id] = {
				['payload'] = payload
			}
			if pkt.fragment ~= nil then
				if fragments_v1[sequence_id] == nil then
					fragments_v1[sequence_id] = {
						['fragment'] = pkt.fragment,
						['payload'] = payload
					}
				end

				local defragmented = fragments_v1[sequence_id]['defragmented']

				if defragmented == nil then
					defragmented = {}
					if pkt.fragment == 0 then
						-- look back in the sequence stream for which packets we are missing (max 50)
						-- TODO: try to do some heuristic here, to see if we likely have to restore or not
						-- this can be based on if a higher fragment id was seen in the past for this stream
						missing = {}
						for i = pkt.seq - 1, math.max(pkt.seq - 50, first_sequence[base_id]), -1 do
							local id = make_sequence_id(i)
							if sequence_stream[id] == nil then
								missing[id] = i
								print("Missing packet " .. id .. " in stream, deferrring fragment restoration")
							end
						end

						for id, _ in pairs(missing) do
							deferred_fragments[id] = {
								['missing'] = missing,
								['sequence_id'] = pkt.seq
							}
						end

						if next(missing) == nil then -- nothing missing, restore the fragments
							local defragmented_payload = nil
							local prev_fragment = fragments_v1[make_sequence_id(pkt.seq - 1)]
							if prev_fragment ~= nil and prev_fragment['fragment'] > pkt.fragment then
								print("Restoring " .. prev_fragment['fragment'] .. " fragments")
								for i = pkt.seq, first_sequence[base_id] - 1, -1 do
									local fragment = fragments_v1[make_sequence_id(i)]
									if fragment == nil then
										error("Cannot find fragment " .. i .. " in the past for packet " .. sequence_id)
										break
									end
									local fragment_payload = fragment['payload']
									if defragmented_payload == nil then
										defragmented_payload = fragment_payload
									else
										defragmented_payload = fragment_payload .. defragmented_payload
									end

									if fragment['fragment'] == 1 then
										break
									end
								end
								defragmented['payload'] = defragmented_payload
								defragmented['size'] = defragmented_payload:len()
								defragmented['fragment'] = pkt.fragment
							else
								-- no additional fragments detected
								defragmented['payload'] = payload
								defragmented['size'] = nil
								-- no need to highlight the packet as fragmented
								defragmented['fragment'] = nil
							end
						end
					else -- missing fragments, attempt to defer defragmentation until a later stage
						local deferred = deferred_fragments[sequence_id]
						if deferred ~= nil then
							print("Found missing packet " .. sequence_id .. " (fragment: " .. pkt.fragment .. ")")
							local missing = deferred['missing']
							for id, _ in pairs(missing) do
								if id == sequence_id then
									missing[id] = nil
								end
							end
							if next(missing) == nil then
								local deferred_sequence_id = deferred['sequence_id']
								print("Found all missing packets, defragmenting from " .. make_sequence_id(deferred_sequence_id))

								local defragmented_payload = nil
								for i = deferred_sequence_id, first_sequence[base_id] - 1, -1 do
									local fragment = fragments_v1[make_sequence_id(i)]
									if fragment == nil then
										error("Cannot find fragment " .. i .. " in the past for packet " .. deferred_sequence_id)
										break
									end
									local fragment_payload = fragment['payload']
									if defragmented_payload == nil then
										defragmented_payload = fragment_payload
									else
										defragmented_payload = fragment_payload .. defragmented_payload
									end

									if fragment['fragment'] == 1 then
										break
									end
								end

								defragmented['payload'] = defragmented_payload
								defragmented['size'] = defragmented_payload:len()
								defragmented['fragment'] = pkt.fragment
							end
						end
					end
					-- save the result of defragmentation (whether successful or not) to the global state in case packets are dissected multiple times (in the GUI)
					fragments_v1[sequence_id]['defragmented'] = defragmented
				end

				-- dump defragmentation results
				if defragmented['payload'] ~= nil then
					subtree:add(F.defragmented_payload, defragmented['payload']:tvb("Defragmented payload"):range())
				end
				pkt.defragmented_size = defragmented['size']
				pkt.fragment = defragmented['fragment']

			end
		end
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
		info = info .. " " .. tostring(payload_size)
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