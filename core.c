#define LUA_LIB
#define _GNU_SOURCE

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
    {NULL, NULL}
};

LUALIB_API int luaopen_sodium_core(lua_State *L) {
  luaL_newlib(L, SodiumLib);
  return 1;
}
