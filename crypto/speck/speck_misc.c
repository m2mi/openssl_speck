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
#include "speck_locl.h"

int Speck_set_key(const unsigned char *userKey, const int bits, SPECK_KEY *key)
{
    if (!userKey || !key)
        return -1;
    /* For the moemnt only 256 bit keys */
    if (bits != 256)
        return -2;
    key->rounds = 4;
    key->rd_key = speck_expand_key_128_256(*(userKey), *(userKey + 8), *(userKey + 16), *(userKey + 24)); 
    return 0;
}

void Speck_encrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key)
{
    speck_encrypt_128_256(key->rd_key, (uint64_t *)in, (uint64_t *)out);
}

void Speck_decrypt(const unsigned char *in, unsigned char *out,
                      const SPECK_KEY *key)
{
    speck_decrypt_128_256(key->rd_key, (uint64_t *)in, (uint64_t *)out);
}