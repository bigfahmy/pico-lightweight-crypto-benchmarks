#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>
#include <stddef.h>

// SPECK 64/128 - 64 bit block, 128 bit key
#define SPECK_ROUNDS 27
#define SPECK_BLOCK_SIZE 8
#define SPECK_KEY_SIZE 16

void speck_key_schedule(const uint32_t key[4], uint32_t round_keys[SPECK_ROUNDS]);

void speck_encrypt_block(const uint32_t round_keys[SPECK_ROUNDS],
                          const uint32_t pt[2], uint32_t ct[2]);

void speck_decrypt_block(const uint32_t round_keys[SPECK_ROUNDS],
                          const uint32_t ct[2], uint32_t pt[2]);

void speck_cbc_encrypt(const uint32_t round_keys[SPECK_ROUNDS],
                        const uint8_t iv[SPECK_BLOCK_SIZE],
                        const uint8_t *plaintext, uint8_t *ciphertext, size_t len);

void speck_cbc_decrypt(const uint32_t round_keys[SPECK_ROUNDS],
                        const uint8_t iv[SPECK_BLOCK_SIZE],
                        const uint8_t *ciphertext, uint8_t *plaintext, size_t len);

#endif