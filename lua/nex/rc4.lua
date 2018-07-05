rc4 = {}

function rc4.new_ks(key)
	local st = {}
	for i = 0, 255 do st[i] = i end
	
	local len = #key
	local j = 0
	for i = 0, 255 do
		j = (j + st[i] + key:byte((i % len) + 1)) % 256
		st[i], st[j] = st[j], st[i]
	end
	
	return {x=0, y=0, st=st}
end

function rc4.crypt(ks, input)
	local x, y, st = ks.x, ks.y, ks.st
	
	local output_bytes = ByteArray.new()
	output_bytes:set_size(input:len())

	local t = {}
	for i = 0, input:len()-1 do
		x = (x + 1) % 256
		y = (y + st[x]) % 256;
		st[x], st[y] = st[y], st[x]
		output_bytes:set_index(i, bit.bxor(input:get_index(i), st[(st[x] + st[y]) % 256]))
	end
	
	ks.x, ks.y = x, y
	
	return output_bytes
end

return rc4