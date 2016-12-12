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

// Key expansion for 128 bit block size, 256 bit key (4 x uint64)
uint64_t * speck_expand_key_128_256(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t k4)
{
    uint64_t i, idx;
    uint64_t * k = (uint64_t *) malloc(sizeof(uint64_t) * 34);
    uint64_t tk[4];

    tk[0] = k4;
    tk[1] = k3;
    tk[2] = k2;
    tk[3] = k1;
    
    k[0] = tk[0];
    
    for (i=0; i<34 - 1; i++)
    {
        idx = (i % 3) + 1;
        tk[idx] = (RR(tk[idx], 8, 64) + tk[0]) ^ i;
        tk[0] = RL(tk[0], 3, 64) ^ tk[idx];
        k[i+1] = tk[0];
    } 
    return k;
}

// Encryption for 128 bit block size, 256 bit key
int speck_encrypt_128_256(uint64_t * k, uint64_t * pt, uint64_t * ct)
{
    uint64_t i;
    
    uint64_t b[2];
    b[0] = pt[1];
    b[1] = pt[0];
    
    for (i=0; i<34; i++)
    {
        b[1] = (RR(b[1], 8, 64) + b[0]) ^ k[i];
        b[0] = RL(b[0], 3, 64) ^ b[1];
    }
    
    ct[0] = b[1];
    ct[1] = b[0];
    
    return 1;
}


// Decryption for 128 bit block size, 256 bit key
int speck_decrypt_128_256(uint64_t * k, uint64_t * ct, uint64_t * pt)
{
    uint64_t i;
    
    uint64_t b[2];
    b[0] = ct[1];
    b[1] = ct[0];
    
    for (i=34; i>0; i--)
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

void xor128(uint64_t * result, uint64_t * a, uint64_t * b)
{
    result[0] = a[0] ^ b[0];
    result[1] = a[1] ^ b[1];
}

size_t speck_128_256_cbc_encrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t k4, uint64_t iv1, uint64_t iv2, void * plaintext, void * ciphertext, size_t length)
{
    size_t i = 0;
    int block_size = sizeof(uint64_t) * 2;
    size_t blocks = length / block_size;
    uint8_t padding_bytes = (int) (block_size - (length - blocks * block_size));
    if (padding_bytes == 0) padding_bytes = block_size;
    uint64_t * kx = speck_expand_key_128_256(k1, k2, k3, k4);
    uint64_t last[2];
    uint64_t x[2];
    last[0] = iv2;
    last[1] = iv1;
    uint64_t last_block[2];
    uint8_t * last_block_bytes = (uint8_t *) &last_block;
    uint64_t * pt = (uint64_t *) plaintext;
    uint64_t * ct = (uint64_t *) ciphertext;
    do
    {
        xor128(x, pt, last);
        speck_encrypt_128_256(kx, x, ct);
        last[0] = ct[0];
        last[1] = ct[1];
        ct+=2;
        pt+=2;
        i++;
    } while (i < blocks);
    
    // Create last padded block
    pt = (uint64_t *) plaintext;
    memcpy(&last_block, &pt[i], block_size - padding_bytes);
    memset(&last_block_bytes[block_size - padding_bytes], (uint8_t) padding_bytes, padding_bytes);
    
    xor128(x, last_block, last);
    speck_encrypt_128_256(kx, x, ct);
    i++;
    
    free(kx);
    return (i * block_size);
}

size_t speck_128_256_cbc_decrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t k4, uint64_t iv1, uint64_t iv2, void * ciphertext, void * plaintext, size_t length)
{
    size_t i = 0;
    int block_size = sizeof(uint64_t) * 2;
    size_t blocks = length / block_size;
    uint8_t padding_bytes;
    uint64_t * kx = speck_expand_key_128_256(k1, k2, k3, k4);
    uint64_t last[2];
    uint64_t x[2];
    last[0] = iv2;
    last[1] = iv1;
    uint64_t * pt = (uint64_t *) plaintext;
    uint64_t * ct = (uint64_t *) ciphertext;
    do
    {
        speck_decrypt_128_256(kx, ct, x);
        xor128(pt, x, last);
        last[0] = ct[0];
        last[1] = ct[1];
        ct+=2;
        pt+=2;
        i++;
    } while (i < blocks);
    
    free(kx);
    
    // Check for padding bytes
    uint8_t * pt_bytes = (uint8_t *) plaintext;
    padding_bytes = pt_bytes[i * block_size -1];
    if (padding_bytes > block_size) return 0;
    int j;
    for (j=0; j<padding_bytes; j++) if (pt_bytes[i * block_size -1 - j] != padding_bytes)
    {
        // Error in padding
        return 0;
    }
    
    return (i * block_size - padding_bytes);
}