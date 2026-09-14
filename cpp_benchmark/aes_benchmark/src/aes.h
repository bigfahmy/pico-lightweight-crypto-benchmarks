#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

// AES-128, 128 bit block, 128 bit key, 10 rounds, CBC mode
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define AES_ROUNDS 10
#define AES_ROUND_KEYS (AES_ROUNDS + 1)

void aes128_key_expansion(const uint8_t key[AES_KEY_SIZE], uint8_t round_keys[AES_ROUND_KEYS][AES_BLOCK_SIZE]);

void aes128_encrypt_block(const uint8_t round_keys[AES_ROUND_KEYS][AES_BLOCK_SIZE],
                           const uint8_t pt[AES_BLOCK_SIZE], uint8_t ct[AES_BLOCK_SIZE]);

void aes128_decrypt_block(const uint8_t round_keys[AES_ROUND_KEYS][AES_BLOCK_SIZE],
                           const uint8_t ct[AES_BLOCK_SIZE], uint8_t pt[AES_BLOCK_SIZE]);

void aes128_cbc_encrypt(const uint8_t round_keys[AES_ROUND_KEYS][AES_BLOCK_SIZE],
                         const uint8_t iv[AES_BLOCK_SIZE],
                         const uint8_t *plaintext, uint8_t *ciphertext, size_t len);

void aes128_cbc_decrypt(const uint8_t round_keys[AES_ROUND_KEYS][AES_BLOCK_SIZE],
                         const uint8_t iv[AES_BLOCK_SIZE],
                         const uint8_t *ciphertext, uint8_t *plaintext, size_t len);

#endif
