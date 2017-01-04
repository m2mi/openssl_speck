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

#ifndef speck_h
#define speck_h

#include <stdlib.h>
#include <stdint.h>

/* Best option on 32-bit machines, key size is 128 bit and considered secure */
uint32_t * speck_expand_key_64_128(uint64_t k1, uint64_t k2);
int speck_encrypt_64_128(uint32_t * k, uint32_t * plaintext, uint32_t * ciphertext);
int speck_decrypt_64_128(uint32_t * k, uint32_t * ciphertext, uint32_t * plaintext);

/* Best option on 64-bit machines, key size is 256 bit */
uint64_t * speck_expand_key_128_256(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t k4);
int speck_encrypt_128_256(uint64_t * k, uint64_t * plaintext, uint64_t * ciphertext);
int speck_decrypt_128_256(uint64_t * k, uint64_t * ciphertext, uint64_t * plaintext);

#endif /* speck_h */