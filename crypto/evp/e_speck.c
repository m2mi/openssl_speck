#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SPECK
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/speck.h>
#include "evp_locl.h"
#include "internal/evp_int.h"

static int  speck_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc);

/* Speck subkey Structure */
typedef struct {
	SPECK_KEY   ks;
} EVP_SPECK_KEY;

/* Attribute operation for Speck */
#define	data(ctx)	EVP_C_DATA(EVP_SPECK_KEY,ctx)

#define IMPLEMENT_SPECK_CBC(keysize,cbits,iv_len) \
				BLOCK_CIPHER_func_cbc(speck_##keysize,Speck,EVP_SPECK_KEY,ks) \
        		BLOCK_CIPHER_def_cbc(speck_##keysize,EVP_SPECK_KEY, \
                             NID_speck_##keysize, cbits, keysize/8, iv_len, \
                             (0)|EVP_CIPH_FLAG_DEFAULT_ASN1, \
                             speck_init_key, NULL, NULL, NULL, NULL)

IMPLEMENT_SPECK_CBC(128,8,8)
IMPLEMENT_SPECK_CBC(256,16,16)

/* The subkey for Speck is generated. */
static int speck_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	int ret = Speck_set_key(key, ctx->key_len * 8, ctx->cipher_data);
	if (ret < 0) {
		EVPerr(EVP_F_SPECK_INIT_KEY, EVP_R_SPECK_KEY_SETUP_FAILED);
		return 0;
	}
	return 1;
}

#endif
