/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/speck.h>

void Speck_cbc_encrypt(const unsigned char *in, unsigned char *out,
                          size_t len, const SPECK_KEY *key,
                          unsigned char *ivec, const int enc)
{

	int BLOCK_SIZE = key->block_size;

	unsigned long n;
	unsigned char tmp[BLOCK_SIZE];
	const unsigned char *iv = ivec;

	assert(in && out && key && ivec);

	if (enc) {
		while (len >= BLOCK_SIZE) {
			for(n=0; n < BLOCK_SIZE; ++n)
				out[n] = in[n] ^ iv[n];
			Speck_encrypt(out, out, key);
			iv = out;
			len -= BLOCK_SIZE;
			in += BLOCK_SIZE;
			out += BLOCK_SIZE;
		}
		if (len) {
			for(n=0; n < len; ++n)
				out[n] = in[n] ^ iv[n];
			for(n=len; n < BLOCK_SIZE; ++n)
				out[n] = iv[n];
			Speck_encrypt(out, out, key);
			iv = out;
		}
		memcpy(ivec,iv,BLOCK_SIZE);
	} else if (in != out) {
		while (len >= BLOCK_SIZE) {
			Speck_decrypt(in, out, key);
			for(n=0; n < BLOCK_SIZE; ++n)
				out[n] ^= iv[n];
			iv = in;
			len -= BLOCK_SIZE;
			in  += BLOCK_SIZE;
			out += BLOCK_SIZE;
		}
		if (len) {
			Speck_decrypt(in,tmp,key);
			for(n=0; n < len; ++n)
				out[n] = tmp[n] ^ iv[n];
			iv = in;
		}
		memcpy(ivec,iv,BLOCK_SIZE);
	} else {
		while (len >= BLOCK_SIZE) {
			memcpy(tmp, in, BLOCK_SIZE);
			Speck_decrypt(in, out, key);
			for(n=0; n < BLOCK_SIZE; ++n)
				out[n] ^= ivec[n];
			memcpy(ivec, tmp, BLOCK_SIZE);
			len -= BLOCK_SIZE;
			in += BLOCK_SIZE;
			out += BLOCK_SIZE;
		}
		if (len) {
			memcpy(tmp, in, BLOCK_SIZE);
			Speck_decrypt(tmp, out, key);
			for(n=0; n < len; ++n)
				out[n] ^= ivec[n];
			for(n=len; n < BLOCK_SIZE; ++n)
				out[n] = tmp[n];
			memcpy(ivec, tmp, BLOCK_SIZE);
		}
	}

}