if not PROTO_V0 then
	_G["PROTO_V0"] = true
	
require("common")

-- See: https://github.com/Kinnay/NintendoClients/wiki/PRUDP-Protocol

local prudp_v0_proto = Proto("prudpv0", "PRUDPv0")

local F = prudp_v0_proto.fields
F.src = ProtoField.uint8("prudpv0.src", "Source", base.HEX, ports)
F.dst = ProtoField.uint8("prudpv0.dst", "Destination", base.HEX, ports)
F.type = ProtoField.uint16("prudpv0.type", "Type", base.HEX, pkt_types, 0x7)
F.flag_ack = ProtoField.bool("prudpv0.ack", "Ack", base.HEX, nil, 0x08)
F.flag_reliable = ProtoField.bool("prudpv0.reliable", "Reliable", base.HEX, nil, 0x10)
F.flag_need_ack = ProtoField.bool("prudpv0.need_ack", "Need ack", base.HEX, nil, 0x20)
F.flag_has_size = ProtoField.bool("prudpv0.has_size", "Has size", base.HEX, nil, 0x40)
-- what's 0x80? idfk

--F.flag_multi_ack = ProtoField.bool("prudpv0.multi_ack", "Multi ack", base.HEX, nil, 0x2000)

F.session = ProtoField.uint8("prudpv0.session", "Session", base.HEX)
F.packet_sig = ProtoField.bytes("prudpv0.packet_sig", "Packet signature")
F.seq = ProtoField.uint16("prudpv0.seq", "Sequence number", base.HEX)

F.conn_sig = ProtoField.uint32("prudpv0.conn_sig", "Connection signature", base.HEX)
F.fragment = ProtoField.uint8("prudpv0.fragment", "Fragment", base.HEX)
F.size = ProtoField.uint16("prudpv0.size", "Packet size", base.HEX)

F.payload = ProtoField.bytes("prudpv0.payload", "Payload")
F.defragmented_payload = ProtoField.bytes("prudpv0.defragmented_payload", "Defragmented payload")
F.checksum = ProtoField.uint8("prudpv0.checksum", "Checksum", base.HEX)

local fragments_v0 = {}
local sequence_stream = {}
local first_sequence = {}
local deferred_fragments = {}

function prudp_v0_proto.dissector(buf,pinfo,tree)
	pinfo.cols.protocol = "PRUDP v0"
	-- Parse the packet header.

	local subtree = tree:add(prudp_v0_proto, buf(), "PRUDP v0")

	local pkt = {}

	pkt.src = buf(0,1):le_uint()
	subtree:add(F.src, buf(0,1))

	pkt.dst = buf(1,1):le_uint()
	subtree:add(F.dst, buf(1,1))

	local pkt_op_flags = buf(2,1):le_uint()

	pkt.type = bit.band(pkt_op_flags, 0x7)
	subtree:add_le(F.type, buf(2,1))

	local flags = subtree:add(prudp_v0_proto, buf(2,1), "Flags")

	pkt.flags = {}
	pkt.flags.ack = bit.band(pkt_op_flags, 0x08) ~= 0
	flags:add_le(F.flag_ack, buf(2,1))
	pkt.flags.reliable = bit.band(pkt_op_flags, 0x10) ~= 0
	flags:add_le(F.flag_reliable, buf(2,1))
	pkt.flags.need_ack = bit.band(pkt_op_flags, 0x20) ~= 0
	flags:add_le(F.flag_need_ack, buf(2,1))
	pkt.flags.has_size = bit.band(pkt_op_flags, 0x40) ~= 0
	flags:add_le(F.flag_has_size, buf(2,1))

	pkt.session = buf(3,1):le_uint()
	subtree:add(F.session, buf(3,1))
	subtree:add(F.packet_sig, buf(4,4))

	pkt.seq = buf(8,2):le_uint()
	subtree:add_le(F.seq, buf(8, 2))

	-- we're done with the general header now.
	-- parse the packet specific data:

	off = 10
	if pkt.type == 0 or pkt.type == 1 then -- ACKs and CONNECTs have a connection signature.
		subtree:add_le(F.conn_sig, buf(off, 4))
		off = off + 4
	elseif pkt.type == 2 then -- DATA packets have a fragment.
		local fragment_range = buf(off, 1)
		pkt.fragment = fragment_range:le_uint()
		subtree:add_le(F.fragment, fragment_range)
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
				if fragments_v0[sequence_id] == nil then
					fragments_v0[sequence_id] = {
						['fragment'] = pkt.fragment,
						['payload'] = payload
					}
				end

				local defragmented = fragments_v0[sequence_id]['defragmented']

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
								print("While reassembling", make_sequence_id(pkt.seq))
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
							local prev_fragment = fragments_v0[make_sequence_id(pkt.seq - 1)]
							if prev_fragment ~= nil and prev_fragment['fragment'] > pkt.fragment then
								print("Restoring " .. prev_fragment['fragment'] .. " fragments for packet", make_sequence_id(pkt.seq))
								for i = pkt.seq, first_sequence[base_id] - 1, -1 do
									local fragment = fragments_v0[make_sequence_id(i)]
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
								print("Not fragmented",  make_sequence_id(pkt.seq))
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
									local fragment = fragments_v0[make_sequence_id(i)]
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
					fragments_v0[sequence_id]['defragmented'] = defragmented
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
	subtree:add(F.checksum, buf(off, 1))

	if pkt.fragment ~= nil then
		info = info .. " FRAGMENT " .. tostring(pkt.fragment)
	end
	if pkt.session ~= nil then
		info = info .. " SESSION " .. string.format("0x%02x", pkt.session)
	end
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

--udp_table = DissectorTable.get("udp.port")
--udp_table:add(60000, prudp_v0_proto)
--udp_table:add(60111, prudp_v0_proto)
end