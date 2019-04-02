#!/usr/bin/lua

local lua = require('sodium')

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

function replace_char(pos, str, r)
    return ("%s%s%s"):format(str:sub(1,pos-1), r, str:sub(pos+1))
end

--[[ trying to invoke key generation function and random buffer ]]
local test_random = lua.random_buf(24)
print("TEST random data (24 bytes for nonce): ", test_random:tohex())
if test_random:len() ~= 24 then
	print("TEST FAIL! Random generated data len isn't equals to 24")	
	os.exit(-1)
end

local test_key = lua.crypto_aead_xchacha20poly1305_keygen()
print("TEST key generated: ", test_key:tohex())
if test_key:len() ~= 32 then
	print("TEST FAIL! Random generated key len isn't equals to 32")	
	os.exit(-1)
end

print(string.format("\ntest with RFC test vector for xChaChaPoly1305\n"))

local message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
local aad = string.char(
		0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
		0xc4, 0xc5, 0xc6, 0xc7)
local nonce = string.char(
		0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 
		0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 
		0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53)
local key = string.char(
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f)

print(string.format("Original message: %s, len: %d", message, message:len()))
print(string.format("KEY: %s, len: %d", key:tohex(), key:len()))
print(string.format("NONCE: %s, len: %d", nonce:tohex(), nonce:len()))
print(string.format("AAD: %s, len: %d", aad:tohex(), aad:len()))

local ciphertext = lua.crypto_aead_xchacha20poly1305_encrypt(message, aad, nonce, key)
print(string.format('ciphertext: %s, len: %d', ciphertext:tohex(), ciphertext:len()))

if ciphertext:len() ~= (message:len() + 16) then
	print("TEST FAIL! Ciphertext length invalid")	
	os.exit(-1)
end	

local decrypted, rc = lua.crypto_aead_xchacha20poly1305_decrypt(ciphertext, aad, nonce, key)
print('decrypted', decrypted)

if rc ~= 0 then
	print("TEST FAIL, by rc != 0: ", rc)
	os.exit(-1)
end

if decrypted ~= message then
	print("TEST FAIL! Decrypted message != original message")
	os.exit(-1)
end

ciphertext = replace_char(1, ciphertext, "1")
decrypted, rc = lua.crypto_aead_xchacha20poly1305_decrypt(ciphertext, aad, nonce, key)
print('errornous_decrypted', decrypted)
print('errornous_decrypted_rc', rc)

if rc == 0 then
	print("CHANGED CHIPHER: TEST FAIL, by rc == 0")
	os.exit(-1)
end

if decrypted == message then
	print("CHANGED CHIPHER: TEST FAIL. by changed ciphertext decripted into original message")
	os.exit(-1)
end

print(string.format("\ntest with empty AAD (nil string and empty string)\n"))
--[[ nil AAD ]]
aad = nil

ciphertext = lua.crypto_aead_xchacha20poly1305_encrypt(message, aad, nonce, key)
print(string.format('ciphertext: %s, len: %d', ciphertext:tohex(), ciphertext:len()))

if ciphertext:len() ~= (message:len() + 16) then
	print("TEST FAIL! Ciphertext length invalid")	
	os.exit(-1)
end	

decrypted, rc = lua.crypto_aead_xchacha20poly1305_decrypt(ciphertext, aad, nonce, key)
print('decrypted', decrypted)

if rc ~= 0 then
	print("TEST FAIL, by rc != 0: ", rc)
	os.exit(-1)
end

if decrypted ~= message then
	print("TEST FAIL! Decrypted message != original message")
	os.exit(-1)
end

--[[ empty AAD ]]
aad = string.char()

ciphertext = lua.crypto_aead_xchacha20poly1305_encrypt(message, aad, nonce, key)
print(string.format('ciphertext: %s, len: %d', ciphertext:tohex(), ciphertext:len()))

if ciphertext:len() ~= (message:len() + 16) then
	print("TEST FAIL! Ciphertext length invalid")	
	os.exit(-1)
end	

decrypted, rc = lua.crypto_aead_xchacha20poly1305_decrypt(ciphertext, aad, nonce, key)
print('decrypted', decrypted)

if rc ~= 0 then
	print("TEST FAIL, by rc != 0: ", rc)
	os.exit(-1)
end

if decrypted ~= message then
	print("TEST FAIL! Decrypted message != original message")
	os.exit(-1)
end
