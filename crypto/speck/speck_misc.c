/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslv.h>
#include <openssl/speck.h>
#include <string.h>
#include "speck_locl.h"

int Speck_set_key(const unsigned char *userKey, const int bits, SPECK_KEY *key)
{
    if (!userKey || !key)
        return -1;

    if (bits == 128) {
        key->block_size = SPECK_128_BLOCK_SIZE;
        key->rounds = SPECK_128_ROUNDS;
        uint32_t *expanded_key = speck_expand_key_64_128(*(userKey), *(userKey + 8));
        key->rd_key = (unsigned int * const)expanded_key;
        return 0;
    }
    if (bits == 256) {
        key->block_size = SPECK_256_BLOCK_SIZE;
        key->rounds = SPECK_256_ROUNDS;
        uint64_t *expanded_key = speck_expand_key_128_256(*(userKey), *(userKey + 8), *(userKey + 16), *(userKey + 24));
        key->rd_key = (unsigned int * const)expanded_key;
        return 0;
    }

    return -2;
}

void Speck_encrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key)
{
    if(key->block_size == SPECK_128_BLOCK_SIZE) {
        speck_encrypt_64_128(key->rd_key, (uint32_t *)in, (uint32_t *)out);
    }
    if(key->block_size == SPECK_256_BLOCK_SIZE) {
        speck_encrypt_128_256((uint64_t *)key->rd_key, (uint64_t *)in, (uint64_t *)out);
    }
}

void Speck_decrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key)
{
    if(key->block_size == SPECK_128_BLOCK_SIZE) {
        speck_decrypt_64_128(key->rd_key, (uint32_t *)in, (uint32_t *)out);
    }
    if(key->block_size == SPECK_256_BLOCK_SIZE) {
        speck_decrypt_128_256((uint64_t *)key->rd_key, (uint64_t *)in, (uint64_t *)out);
    }
}
