#ifndef PRESENT_H
#define PRESENT_H

#include <stdint.h>
#include <stddef.h>

// PRESENT-80 - 64 bit block, 80 bit key, 31 rounds
#define PRESENT_ROUNDS 31
#define PRESENT_BLOCK_SIZE 8
#define PRESENT_KEY_SIZE 10

// round_keys must hold PRESENT_ROUNDS + 1 (32) subkeys: [0..30] per-round, [31] final whitening
void present_key_schedule(const uint8_t key[PRESENT_KEY_SIZE], uint64_t round_keys[PRESENT_ROUNDS + 1]);

uint64_t present_encrypt_block(const uint64_t round_keys[PRESENT_ROUNDS + 1], uint64_t pt);
uint64_t present_decrypt_block(const uint64_t round_keys[PRESENT_ROUNDS + 1], uint64_t ct);

void present_cbc_encrypt(const uint64_t round_keys[PRESENT_ROUNDS + 1],
                          const uint8_t iv[PRESENT_BLOCK_SIZE],
                          const uint8_t *plaintext, uint8_t *ciphertext, size_t len);

void present_cbc_decrypt(const uint64_t round_keys[PRESENT_ROUNDS + 1],
                          const uint8_t iv[PRESENT_BLOCK_SIZE],
                          const uint8_t *ciphertext, uint8_t *plaintext, size_t len);

#endif
