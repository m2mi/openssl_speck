/*
 * (C) Copyright ${year} Machine-to-Machine Intelligence (M2Mi) Corporation, all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Julien Niset 
 *     Louis-Philippe Lamoureux
 *     William Bathurst
 *     Peter Havart-Simkin
 *     Geoff Barnard
 *     Andrew Whaley
 */

#include <openssl/speck.h>
#include "speck_locl.h"
#include <stdlib.h>
#include <string.h>

#define RR(x, r, w) ((x >> r) | (x << (w - r)))
#define RL(x, r, w) ((x << r) | (x >> (w - r)))

/* ************* Best option on 32-bit machines: 64 bit block, 128 bit key, 27 rounds **************** */

/* Key expansion */
uint32_t * speck_expand_key_64_128(uint64_t k1, uint64_t k2)
{
    uint32_t i, idx;
    uint32_t * k = (uint32_t *) malloc(sizeof(uint32_t) * SPECK_128_ROUNDS);
    uint32_t tk[4];
    uint64_t * m = (uint64_t *) &tk;
    m[0] = k2; m[1] = k1;
    
    k[0] = tk[0];
    
    for (i=0; i<SPECK_128_ROUNDS - 1; i++)
    {
        idx = (i % 3) + 1;
        tk[idx] = (RR(tk[idx], 8, 32) + tk[0]) ^ i;
        tk[0] = RL(tk[0], 3, 32) ^ tk[idx];
        k[i+1] = tk[0];
    }
    return k;
}

/* Encryption */
int speck_encrypt_64_128(uint32_t * k, uint32_t * pt, uint32_t * ct)
{
    uint32_t i;
    
    uint32_t b[2];
    b[0] = pt[1];
    b[1] = pt[0];
    
    for (i=0; i<SPECK_128_ROUNDS; i++)
    {
        b[1] = (RR(b[1], 8, 32) + b[0]) ^ k[i];
        b[0] = RL(b[0], 3, 32) ^ b[1];
    }
    
    ct[0] = b[1];
    ct[1] = b[0];
    
    return 1;
}

/* Decryption */
int speck_decrypt_64_128(uint32_t * k, uint32_t * ct, uint32_t * pt)
{
    uint32_t i;
    
    uint32_t b[2];
    b[0] = ct[1];
    b[1] = ct[0];
    
    for (i=SPECK_128_ROUNDS; i>0; i--)
    {
        b[0] = b[0] ^ b[1];
        b[0] = RR(b[0], 3, 32);
        b[1] = (b[1] ^ k[i-1]) - b[0];
        b[1] = RL(b[1], 8, 32);
    }
    
    pt[0] = b[1];
    pt[1] = b[0];
    
    return 1;
}

/* ************* Best option on 64-bit machines: 128 bit block, 256 bit key, 34 rounds **************** */

/* Key expansion */
uint64_t * speck_expand_key_128_256(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t k4)
{
    uint64_t i, idx;
    uint64_t * k = (uint64_t *) malloc(sizeof(uint64_t) * SPECK_256_ROUNDS);
    uint64_t tk[4];

    tk[0] = k4;
    tk[1] = k3;
    tk[2] = k2;
    tk[3] = k1;
    
    k[0] = tk[0];
    
    for (i=0; i<SPECK_256_ROUNDS - 1; i++)
    {
        idx = (i % 3) + 1;
        tk[idx] = (RR(tk[idx], 8, 64) + tk[0]) ^ i;
        tk[0] = RL(tk[0], 3, 64) ^ tk[idx];
        k[i+1] = tk[0];
    } 
    return k;
}

/* Block Encryption */
int speck_encrypt_128_256(uint64_t * k, uint64_t * pt, uint64_t * ct)
{
    uint64_t i;
    
    uint64_t b[2];
    b[0] = pt[1];
    b[1] = pt[0];
    
    for (i=0; i<SPECK_256_ROUNDS; i++)
    {
        b[1] = (RR(b[1], 8, 64) + b[0]) ^ k[i];
        b[0] = RL(b[0], 3, 64) ^ b[1];
    }
    
    ct[0] = b[1];
    ct[1] = b[0];
    
    return 1;
}


/* Block Decryption */
int speck_decrypt_128_256(uint64_t * k, uint64_t * ct, uint64_t * pt)
{
    uint64_t i;
    
    uint64_t b[2];
    b[0] = ct[1];
    b[1] = ct[0];
    
    for (i=SPECK_256_ROUNDS; i>0; i--)
    {
        b[0] = b[0] ^ b[1];
        b[0] = RR(b[0], 3, 64);
        b[1] = (b[1] ^ k[i-1]) - b[0];
        b[1] = RL(b[1], 8, 64);
    }
    
    pt[0] = b[1];
    pt[1] = b[0];
    
    return 1;
}
