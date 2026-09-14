#include "present.h"
#include <string.h>

static const uint8_t PRESENT_SBOX[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};
static const uint8_t PRESENT_INV_SBOX[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};
static const uint8_t PRESENT_P[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};
static uint8_t PRESENT_INV_P[64];

static uint64_t load64_be(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void store64_be(uint8_t *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static uint64_t sbox_layer(uint64_t state, const uint8_t sbox[16]) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (uint8_t)((state >> (4 * i)) & 0xF);
        result |= (uint64_t)sbox[nibble] << (4 * i);
    }
    return result;
}

static uint64_t permute_table(uint64_t source, const uint8_t table[64]) {
    uint64_t result = 0;
    for (int i = 0; i < 64; i++) {
        int distance = 63 - i;
        uint64_t bit = (source >> distance) & 0x1ULL;
        result |= bit << (63 - table[i]);
    }
    return result;
}

void present_key_schedule(const uint8_t key[PRESENT_KEY_SIZE], uint64_t round_keys[PRESENT_ROUNDS + 1]) {
    uint64_t keyHigh = load64_be(key);
    uint32_t keyLow = ((uint32_t)key[8] << 8) | key[9];

    round_keys[0] = keyHigh;
    for (int i = 1; i <= PRESENT_ROUNDS; i++) {
        uint64_t temp1 = keyHigh;
        uint32_t temp2 = keyLow;

        // rotate the 80-bit key register left by 61 bits
        keyHigh = (keyHigh << 61) | ((uint64_t)temp2 << 45) | (temp1 >> 19);
        keyLow = (uint32_t)((temp1 >> 3) & 0xFFFF);

        // most significant nibble through the S-box
        uint8_t topNibble = (uint8_t)(keyHigh >> 60);
        uint8_t sboxed = PRESENT_SBOX[topNibble];
        keyHigh = (keyHigh & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)sboxed << 60);

        // round counter XORed into bits k19..k15
        keyLow = keyLow ^ ((uint32_t)(i & 0x01) << 15);
        keyHigh = keyHigh ^ (uint32_t)(i >> 1);

        round_keys[i] = keyHigh;
    }

    for (int i = 0; i < 64; i++) PRESENT_INV_P[PRESENT_P[i]] = (uint8_t)i;
}

uint64_t present_encrypt_block(const uint64_t round_keys[PRESENT_ROUNDS + 1], uint64_t pt) {
    uint64_t state = pt;
    for (int i = 0; i < PRESENT_ROUNDS; i++) {
        state ^= round_keys[i];
        state = sbox_layer(state, PRESENT_SBOX);
        state = permute_table(state, PRESENT_P);
    }
    state ^= round_keys[PRESENT_ROUNDS];
    return state;
}

uint64_t present_decrypt_block(const uint64_t round_keys[PRESENT_ROUNDS + 1], uint64_t ct) {
    uint64_t state = ct ^ round_keys[PRESENT_ROUNDS];
    for (int i = PRESENT_ROUNDS - 1; i >= 0; i--) {
        state = permute_table(state, PRESENT_INV_P);
        state = sbox_layer(state, PRESENT_INV_SBOX);
        state ^= round_keys[i];
    }
    return state;
}

void present_cbc_encrypt(const uint64_t round_keys[PRESENT_ROUNDS + 1],
                          const uint8_t iv[PRESENT_BLOCK_SIZE],
                          const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    uint8_t prev[PRESENT_BLOCK_SIZE];
    memcpy(prev, iv, PRESENT_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += PRESENT_BLOCK_SIZE) {
        uint8_t block[PRESENT_BLOCK_SIZE];
        for (int j = 0; j < PRESENT_BLOCK_SIZE; j++)
            block[j] = plaintext[i + j] ^ prev[j];

        uint64_t ct = present_encrypt_block(round_keys, load64_be(block));
        store64_be(&ciphertext[i], ct);
        memcpy(prev, &ciphertext[i], PRESENT_BLOCK_SIZE);
    }
}

void present_cbc_decrypt(const uint64_t round_keys[PRESENT_ROUNDS + 1],
                          const uint8_t iv[PRESENT_BLOCK_SIZE],
                          const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
    uint8_t prev[PRESENT_BLOCK_SIZE];
    memcpy(prev, iv, PRESENT_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += PRESENT_BLOCK_SIZE) {
        uint64_t pt = present_decrypt_block(round_keys, load64_be(&ciphertext[i]));
        uint8_t block[PRESENT_BLOCK_SIZE];
        store64_be(block, pt);

        for (int j = 0; j < PRESENT_BLOCK_SIZE; j++)
            plaintext[i + j] = block[j] ^ prev[j];

        memcpy(prev, &ciphertext[i], PRESENT_BLOCK_SIZE);
    }
}
