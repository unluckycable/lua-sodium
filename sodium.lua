--[[
  #!/usr/bin/lua

  local lua = require('sodium')

  -- print("test:", lua.test())
  local message = "test"
  print('message orig', message)
  local additional_data = "123456"
  local nonce = lua.random_buf(24)
  -- print("nonce:", nonce)
  local key = lua.keygen()
  -- print('key', key)
  local ciphertext, ciphertext_len = lua.encrypt_buffer(message, additional_data, nonce, key)
  -- print('ciphertext', ciphertext)
  -- print('ciphertext_len', ciphertext_len)
  local decrypted = lua.decrypt_buffer(ciphertext, ciphertext_len, additional_data, nonce, key)
  print('decrypted', decrypted)

]]

local sodium = require("sodium.core")

local M = {
  test = sodium.test,
  random_buf = sodium.random_buf,
  keygen = sodium.keygen,
  encrypt_buffer = sodium.encrypt_buffer,
  decrypt_buffer = sodium.decrypt_buffer
}

return M
