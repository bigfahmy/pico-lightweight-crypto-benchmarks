#include "speck.h"
#include <string.h>

#define ROR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define ROL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

void speck_key_schedule(const uint32_t key[4], uint32_t round_keys[SPECK_ROUNDS]) {
    uint32_t A = key[0];
    uint32_t B[3] = {key[1], key[2], key[3]};
    
    round_keys[0] = A;
    for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
        B[i % 3] = (ROR32(B[i % 3], 8) + A) ^ i;
        A = ROL32(A, 3) ^ B[i % 3];
        round_keys[i + 1] = A;
    }
}

void speck_encrypt_block(const uint32_t round_keys[SPECK_ROUNDS],
                          const uint32_t pt[2], uint32_t ct[2]) {
    uint32_t x = pt[0], y = pt[1];
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        x = (ROR32(x, 8) + y) ^ round_keys[i];
        y = ROL32(y, 3) ^ x;
    }
    ct[0] = x;
    ct[1] = y;
}

void speck_decrypt_block(const uint32_t round_keys[SPECK_ROUNDS],
                          const uint32_t ct[2], uint32_t pt[2]) {
    uint32_t x = ct[0], y = ct[1];
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        y = ROR32(x ^ y, 3);
        x = ROL32((x ^ round_keys[i]) - y, 8);
    }
    pt[0] = x;
    pt[1] = y;
}

void speck_cbc_encrypt(const uint32_t round_keys[SPECK_ROUNDS],
                        const uint8_t iv[SPECK_BLOCK_SIZE],
                        const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    uint8_t prev[SPECK_BLOCK_SIZE];
    memcpy(prev, iv, SPECK_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
        uint8_t block[SPECK_BLOCK_SIZE];
        for (int j = 0; j < SPECK_BLOCK_SIZE; j++)
            block[j] = plaintext[i + j] ^ prev[j];

        uint32_t pt32[2], ct32[2];
        memcpy(pt32, block, SPECK_BLOCK_SIZE);
        speck_encrypt_block(round_keys, pt32, ct32);
        memcpy(&ciphertext[i], ct32, SPECK_BLOCK_SIZE);
        memcpy(prev, &ciphertext[i], SPECK_BLOCK_SIZE);
    }
}

void speck_cbc_decrypt(const uint32_t round_keys[SPECK_ROUNDS],
                        const uint8_t iv[SPECK_BLOCK_SIZE],
                        const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
    uint8_t prev[SPECK_BLOCK_SIZE];
    memcpy(prev, iv, SPECK_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
        uint32_t ct32[2], pt32[2];
        memcpy(ct32, &ciphertext[i], SPECK_BLOCK_SIZE);
        speck_decrypt_block(round_keys, ct32, pt32);

        uint8_t block[SPECK_BLOCK_SIZE];
        memcpy(block, pt32, SPECK_BLOCK_SIZE);
        for (int j = 0; j < SPECK_BLOCK_SIZE; j++)
            plaintext[i + j] = block[j] ^ prev[j];

        memcpy(prev, &ciphertext[i], SPECK_BLOCK_SIZE);
    }
}