local function string_xor(s1, s2)
	assert(#s1 == #s2, 'strings must be of equal length')
	local buf = ""
	for i=1,#s1 do
		buf = buf .. string.char(bit.bxor(s1:byte(i), s2:byte(i)))
	end
	return buf
end

--any hash function works, md5, sha256, etc.
--blocksize is that of the underlying hash function (64 for MD5 and SHA-256, 128 for SHA-384 and SHA-512)
local function compute(key, message, hash, blocksize, opad, ipad)
   if #key > blocksize then
		key = hash(key) --keys longer than blocksize are shortened
   end
   key = key .. string.rep('\0', blocksize - #key) --keys shorter than blocksize are zero-padded
   opad = opad or string_xor(key, string.rep(string.char(0x5c), blocksize))
   ipad = ipad or string_xor(key, string.rep(string.char(0x36), blocksize))
	return hash(opad .. hash(ipad .. message)), opad, ipad --opad and ipad can be cached for the same key
end

local hmac = {
	new = new,
	compute = compute,
}

return hmac