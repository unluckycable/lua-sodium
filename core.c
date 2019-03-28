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

const static int keygen(lua_State *L) {
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

const static int encrypt_buffer(lua_State * L) {
  const unsigned int argc = lua_gettop(L);
  unsigned char * ciphertext = NULL;
  unsigned long long ciphertext_len;

  if (argc < 4) {
    fprintf(stderr, "you must pass 4 arguments: encrypt_buffer(message, additional_data, nonce, key)!\n");
    goto err;
  }

  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be string: message!\n");
    goto err;
  }
  const unsigned char *message = strdupa(luaL_checkstring(L, 1));
  const size_t message_len = strlen(message);
  if (message_len == 0) {
    fprintf(stderr, "message length should greater then zero!\n");
    goto err;
  }

  if (lua_isstring(L, 2) != 1) {
    fprintf(stderr, "second argument must be string: additional_data!\n");
    goto err;
  }
  const unsigned char *additional_data = strdupa(luaL_checkstring(L, 2));
  const size_t additional_data_len = strlen(additional_data);
  if (additional_data_len == 0) {
    fprintf(stderr, "additional_data length should greater then zero!\n");
    goto err;
  }

  if (lua_isstring(L, 3) != 1) {
    fprintf(stderr, "third argument must be string: nonce!\n");
    goto err;
  }
  const unsigned char *nonce = strdupa(luaL_checkstring(L, 3));
  const size_t nonce_len = strlen(nonce);
  if (nonce_len == 0) {
    fprintf(stderr, "nonce length should greater then zero!\n");
    goto err;
  }

    
  if (lua_isstring(L, 4) != 1) {
    fprintf(stderr, "fourth argument must be string: key!\n");
    goto err;
  }
  const unsigned char *key = strdupa(luaL_checkstring(L, 4));
  const size_t key_len = strlen(key);
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
  lua_pushnumber(L, ciphertext_len);
  free(ciphertext);
  return 2;
 err:
  return 0;
}



const static int decrypt_buffer(lua_State * L) {
  const unsigned int argc = lua_gettop(L);
  if (argc < 5) {
    fprintf(stderr, "you must pass 5 arguments: decrypt_buffer(ciphertext, ciphertext_len, additional_data, nonce, key)!\n");
    goto err;
  }
  unsigned char * decrypted = NULL;
  unsigned long long decrypted_len;

  const size_t decrypted_size = 1025;
  if ((decrypted = malloc(decrypted_size)) == 0) {
    fprintf(stderr, "decrypt_buffer: Out of memory!\n%s\n", strerror(errno));
    goto err;
  }

  memset(decrypted, 0, decrypted_size);

  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be a string: ciphertext!\n");
    goto err;
  }
  const unsigned char *ciphertext = strdupa(luaL_checkstring(L, 1));


  if (lua_isnumber(L, 2) != 1) {
    fprintf(stderr, "second argument must be a number: ciphertext_len!\n");
    goto err;
  }
  const unsigned long long ciphertext_len = luaL_checknumber(L, 2);

  if (lua_isstring(L, 3) != 1) {
    fprintf(stderr, "third argument must be string: additional_data!\n");
    goto err;
  }
  const unsigned char *additional_data = strdupa(luaL_checkstring(L, 3));
  const size_t additional_data_len = strlen(additional_data);
  if (additional_data_len == 0) {
    fprintf(stderr, "additional_data length should greater then zero!\n");
    goto err;
  }

  if (lua_isstring(L, 4) != 1) {
    fprintf(stderr, "fourth argument must be string: nonce!\n");
    goto err;
  }
  const unsigned char *nonce = strdupa(luaL_checkstring(L, 4));
  const size_t nonce_len = strlen(nonce);
  if (nonce_len == 0) {
    fprintf(stderr, "nonce length should greater then zero!\n");
    goto err;
  }

  if (lua_isstring(L, 5) != 1) {
    fprintf(stderr, "fifth argument must be string: key!\n");
    goto err;
  }
  const unsigned char *key = strdupa(luaL_checkstring(L, 5));
  const size_t key_len = strlen(key);
  if (key_len == 0) {
    fprintf(stderr, "key length should greater then zero!\n");
    goto err;
  }

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
						 NULL,
						 ciphertext, ciphertext_len,
						 additional_data,
						 additional_data_len,
						 nonce, key) != 0) {
    /* message forged! */
    printf("Error\n");
  } else {
    printf("Success\n");
  }

  lua_pushstring(L, decrypted);
  free(decrypted);
  return 1;
 err:
  return 0;
}



const static int _test() {

  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char ciphertext[MESSAGE_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned long long ciphertext_len;

  crypto_aead_xchacha20poly1305_ietf_keygen(key);
  randombytes_buf(nonce, sizeof nonce);
  crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
					     MESSAGE, MESSAGE_LEN,
					     ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
					     NULL, nonce, key);

  unsigned char decrypted[MESSAGE_LEN];
  unsigned long long decrypted_len;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
						 NULL,
						 ciphertext, ciphertext_len,
						 ADDITIONAL_DATA,
						 ADDITIONAL_DATA_LEN,
						 nonce, key) != 0) {
    /* message forged! */
  }
  return 0;
}


const static int test(lua_State * L) {
  int code;
  // const int argc = lua_gettop(L);
  code = _test();
  printf("\nHello world!!! code == \"%d\"\n", code);
  return code;
}

// Register library using this array
static const struct luaL_Reg SodiumLib[] = {
    {"test", test},
    {"random_buf", random_buffer},
    {"keygen", keygen},
    {"encrypt_buffer", encrypt_buffer},
    {"decrypt_buffer", decrypt_buffer},
    {NULL, NULL}
};

LUALIB_API int luaopen_sodium_core(lua_State *L) {
  luaL_newlib(L, SodiumLib);
  return 1;
}
