#define LUA_LIB
#define _GNU_SOURCE

#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdlib.h>
#include <string.h>

#if LUA_VERSION_NUM < 502
#define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#define luaL_setfuncs(L,l,n) (assert(n==0), luaL_register(L,NULL,l))
#define luaL_checkunsigned(L,n) luaL_checknumber(L,n)
#endif

#if LUA_VERSION_NUM >= 503
#ifndef luaL_checkunsigned
#define luaL_checkunsigned(L,n) ((lua_Unsigned)luaL_checkinteger(L,n))
#endif
#endif

#ifdef NO_CHECK_UDATA
#define checkudata(L,i,tname)	lua_touserdata(L, i)
#else
#define checkudata(L,i,tname)	luaL_checkudata(L, i, tname)
#endif

#define lua_boxpointer(L,u) \
    (*(void **) (lua_newuserdata(L, sizeof(void *))) = (u))

#define lua_unboxpointer(L,i,tname) \
    (*(void **) (checkudata(L, i, tname)))

/* Max Lua arguments for function */
#define MAXVARS	200

#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

const static int random_buffer(lua_State * L) {
  const unsigned int argc = lua_gettop(L);
  unsigned char * buffer = NULL;

  if (argc < 1) {
    fprintf(stderr, "you must pass one argument: random_buf len!\n");
    goto err;
  }

  if (luaL_checkinteger(L, 1) < 0) {
    fprintf(stderr, "first argument must be positive integer!\n");
    goto err;
  }

  const size_t size = (unsigned int) luaL_checkint(L, 1);
  if ((buffer = malloc(size)) == 0) {
    fprintf(stderr, "random_buffer: Out of memory!\n%s\n", strerror(errno));
    goto err;
  }

  memset(buffer, 0, size);
  randombytes_buf(buffer, size);
  lua_pushlstring(L, buffer, size);
  free(buffer);
  return 1;

 err:
  return 0;
}

const static int crypto_aead_xchacha20poly1305_keygen(lua_State *L) {
  unsigned char * key = NULL;
  if ((key = malloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)) == 0) {
    fprintf(stderr, "keygen: Out of memory!\n%s\n", strerror(errno));
    goto err;
  }
  memset(key, 0, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  crypto_aead_xchacha20poly1305_ietf_keygen(key);
  lua_pushlstring(L, key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  free(key);
  return 1;
 err:
  return 0;
}

const static int crypto_aead_xchacha20poly1305_encrypt(lua_State * L) {
  const unsigned int argc = lua_gettop(L);
  unsigned char * ciphertext = NULL;
  unsigned long long ciphertext_len;

  if (argc < 4) {
    fprintf(stderr, "you must pass 4 arguments: encrypt_buffer(message, additional_data (can be nil), nonce, key)!\n");
    goto err;
  }

  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be string: message!\n");
    goto err;
  }
  
  size_t message_len = 0;
  const char *message = luaL_checklstring(L, 1, &message_len);
  if (message_len == 0) {
    fprintf(stderr, "message length should greater then zero!\n");
    goto err;
  }

  size_t additional_data_len = 0;
  const unsigned char *additional_data = NULL;  
  
  if (lua_isstring(L, 2) == 1) {
    additional_data = luaL_checklstring(L, 2, &additional_data_len);
  } else if (lua_isnil(L, 2) == 1) {	  
	  // additional data can be empty
  } else {
	  fprintf(stderr, "second argument must be string or nil: additional_data!\n");
	  goto err;
  }  

  if (lua_isstring(L, 3) != 1) {
    fprintf(stderr, "third argument must be string: nonce!\n");
    goto err;
  }
  
  size_t nonce_len = 0;
  const char *nonce = luaL_checklstring(L, 3, &nonce_len);  
  if (nonce_len == 0) {
    fprintf(stderr, "nonce length should greater then zero!\n");
    goto err;
  }
    
  if (lua_isstring(L, 4) != 1) {
    fprintf(stderr, "fourth argument must be string: key!\n");
    goto err;
  }
  
  size_t key_len = 0;
  const char *key = luaL_checklstring(L, 4, &key_len);  
  if (key_len == 0) {
    fprintf(stderr, "key length should greater then zero!\n");
    goto err;
  }

  size_t size_ciphertext = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if ((ciphertext = malloc(size_ciphertext)) == 0) {
    fprintf(stderr, "encrypt_buffer: Out of memory!\n%s\n", strerror(errno));
    goto err;
  }
  memset(ciphertext, 0, size_ciphertext);
  
  crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
					     message, message_len,
					     additional_data, additional_data_len,
					     NULL, nonce, key);
					     
  lua_pushlstring(L, ciphertext, size_ciphertext);
  
  free(ciphertext);
  return 1;
 err:
  return 0;
}

const static int crypto_aead_xchacha20poly1305_decrypt(lua_State * L) {
  const unsigned int argc = lua_gettop(L);
  if (argc < 4) {
    fprintf(stderr, "you must pass 4 arguments: decrypt_buffer(ciphertext, additional_data, nonce, key)!\n");
    goto err;
  }  

  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be a string: ciphertext!\n");
    goto err;  
  }
  
  size_t ciphertext_len = 0;
  const unsigned char *ciphertext = luaL_checklstring(L, 1, &ciphertext_len);   
  if (ciphertext_len == 0) {
    fprintf(stderr, "ciphertext length should greater then zero!\n");
    goto err;
  }

  unsigned char * decrypted = NULL;
  unsigned long long decrypted_len = ciphertext_len;
    if ((decrypted = malloc(decrypted_len)) == 0) {
    fprintf(stderr, "decrypt_buffer: Out of memory!\n%s\n", strerror(errno));
    goto err;
  }
  memset(decrypted, 0, decrypted_len);
  
  size_t additional_data_len = 0;
  const unsigned char *additional_data = NULL; 
  
  if (lua_isstring(L, 2) == 1) {
    additional_data = luaL_checklstring(L, 2, &additional_data_len);
  } else if (lua_isnil(L, 2) == 1) {	  
	  // additional data can be empty
  } else {
	  fprintf(stderr, "second argument must be string or nil: additional_data!\n");
	  goto err;
  } 
  
  if (lua_isstring(L, 3) != 1) {
    fprintf(stderr, "third argument must be string: nonce!\n");
    goto err;
  }
  
  size_t nonce_len = 0;
  const unsigned char *nonce = luaL_checklstring(L, 3, &nonce_len);
  if (nonce_len == 0) {
    fprintf(stderr, "nonce length should greater then zero!\n");
    goto err;
  }

  if (lua_isstring(L, 4) != 1) {
    fprintf(stderr, "fourth argument must be string: key!\n");
    goto err;
  }
  
  size_t key_len = 0;
  const unsigned char *key = luaL_checklstring(L, 4, &key_len);
  if (key_len == 0) {
    fprintf(stderr, "key length should greater then zero!\n");
    goto err;
  }

  int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
						 NULL,
						 ciphertext, ciphertext_len,
						 additional_data,
						 additional_data_len,
						 nonce, key);

  lua_pushlstring(L, decrypted, decrypted_len);
  lua_pushnumber(L, rc);
  
  free(decrypted);
  return 2;
 err:
  return 0;
}

// Register library using this array
static const struct luaL_Reg SodiumLib[] = {
    {"random_buf", random_buffer},
    {"crypto_aead_xchacha20poly1305_keygen", crypto_aead_xchacha20poly1305_keygen},
    {"crypto_aead_xchacha20poly1305_encrypt", crypto_aead_xchacha20poly1305_encrypt},
    {"crypto_aead_xchacha20poly1305_decrypt", crypto_aead_xchacha20poly1305_decrypt},
    {NULL, NULL}
};

LUALIB_API int luaopen_sodium_core(lua_State *L) {
  luaL_newlib(L, SodiumLib);
  return 1;
}
