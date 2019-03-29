local sodium = require("sodium.core")

local M = {
  random_buf = sodium.random_buf,
  crypto_aead_xchacha20poly1305_keygen = sodium.crypto_aead_xchacha20poly1305_keygen,
  crypto_aead_xchacha20poly1305_encrypt = sodium.crypto_aead_xchacha20poly1305_encrypt,
  crypto_aead_xchacha20poly1305_decrypt = sodium.crypto_aead_xchacha20poly1305_decrypt
}

return M
