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

# ifndef OPENSSL_NO_SPECK
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

# define SPECK_ENCRYPT        1
# define SPECK_DECRYPT        0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */

/* This should be a hidden type, but EVP requires that the size be known */

/* M2Mi: define block size and rounds?? */
# define SPECK_BLOCK_SIZE 16

/* M2Mi: Should be the result of Key Expansion */
struct speck_key_st {
    unsigned long long *rd_key;
    int rounds;
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
void Speck_cbc_decrypt(const unsigned char *in, unsigned char *out,
                          size_t length, const SPECK_KEY *key,
                          unsigned char *ivec, const int enc);

# ifdef  __cplusplus
}
# endif
# endif

#endif
