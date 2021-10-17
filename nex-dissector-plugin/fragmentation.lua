local fragments_v0 = {}
local fragments_v1 = {}
local sequence_stream = {}
local first_sequence = {}
local deferred_fragments = {}

local f_defragmented_payload_v0 = Field.new("prudpv0.defragmented_payload")
local f_defragmented_payload_v1 = Field.new("prudpv1.defragmented_payload")

function defragment(version, subtree, pkt, pinfo, payload_range, defragmented_payload_field)
	local fragments
	if version == 0 then
		fragments = fragments_v0
	elseif version == 1 then
		fragments = fragments_v1
	end

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
			if fragments[sequence_id] == nil then
				fragments[sequence_id] = {
					['fragment'] = pkt.fragment,
					['payload'] = payload
				}
			end

			local defragmented = fragments[sequence_id]['defragmented']

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
						local prev_fragment = fragments[make_sequence_id(pkt.seq - 1)]
						if prev_fragment ~= nil and prev_fragment['fragment'] > pkt.fragment then
							print("Restoring " .. prev_fragment['fragment'] .. " fragments")
							for i = pkt.seq, first_sequence[base_id] - 1, -1 do
								local fragment = fragments[make_sequence_id(i)]
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
								local fragment = fragments[make_sequence_id(i)]
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
				fragments[sequence_id]['defragmented'] = defragmented
			end

			-- dump defragmentation results
			if defragmented['payload'] ~= nil then
				subtree:add(defragmented_payload_field, defragmented['payload']:tvb("Defragmented payload"):range())
			end
			pkt.defragmented_size = defragmented['size']
			-- pkt.fragment = defragmented['fragment']
		end
	end
end