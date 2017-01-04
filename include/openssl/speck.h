/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SPECK_H
# define HEADER_SPECK_H

# include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SPECK
# include <stddef.h>
# include <stdlib.h>
# include <stdint.h>
#ifdef  __cplusplus
extern "C" {
#endif

# define SPECK_ENCRYPT        1
# define SPECK_DECRYPT        0

/* Define block size and rounds for 128 and 256 bit keys */
# define SPECK_128_BLOCK_SIZE 8
# define SPECK_128_ROUNDS 27
# define SPECK_256_BLOCK_SIZE 16
# define SPECK_256_ROUNDS 34

/* Contains the result of key expansion */
struct speck_key_st {
	int block_size;
	int rounds;
    uint32_t *rd_key;
};
typedef struct speck_key_st SPECK_KEY;

int Speck_set_key(const unsigned char *userKey, const int bits,
                     SPECK_KEY *key);

void Speck_encrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key);

void Speck_decrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key);

void Speck_cbc_encrypt(const unsigned char *in, unsigned char *out,
                          size_t len, const SPECK_KEY *key,
                          unsigned char *ivec, const int enc);

# ifdef  __cplusplus
}
# endif
# endif

#endif
