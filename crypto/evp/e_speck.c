#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SPECK
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/speck.h>
#include "evp_locl.h"
//#include "../include/internal/evp_int.h"

static int speck_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

/* Speck subkey Structure */
typedef struct {
	SPECK_KEY ks;
} EVP_SPECK_KEY;

/* Attribute operation for Speck */
#define data(ctx)		EVP_C_DATA(EVP_SPECK_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(speck_128, ks, Speck, EVP_SPECK_KEY, 
	NID_speck_128, 16, 16, 16, 128,
	0, speck_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL)

/* The subkey for Speck is generated. */
static int speck_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
	int ret;
	if (enc) 
		ret=Speck_set_key(key, ctx->key_len * 8, ctx->cipher_data);
	else
		ret=Speck_set_key(key, ctx->key_len * 8, ctx->cipher_data);
	if(ret < 0)
	{ 
		EVPerr(EVP_F_SPECK_INIT_KEY,EVP_R_SPECK_KEY_SETUP_FAILED); 
		return 0;
	}
	return 1; 
}

#else

#endif