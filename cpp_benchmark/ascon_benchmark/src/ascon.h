#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

// Ascon-AEAD128 - 128 bit key, 128 bit nonce, 128 bit tag, 16 byte rate, p^12/p^8 permutations
#define ASCON_KEY_SIZE   16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE   16
#define ASCON_RATE       16

void ascon_aead_encrypt(const uint8_t key[ASCON_KEY_SIZE],
                         const uint8_t nonce[ASCON_NONCE_SIZE],
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *plaintext, size_t len,
                         uint8_t *ciphertext, uint8_t tag[ASCON_TAG_SIZE]);

// Always fully computes plaintext; returns 0 if the tag is valid, -1 otherwise.
int ascon_aead_decrypt(const uint8_t key[ASCON_KEY_SIZE],
                        const uint8_t nonce[ASCON_NONCE_SIZE],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *ciphertext, size_t len,
                        const uint8_t tag[ASCON_TAG_SIZE],
                        uint8_t *plaintext);

#endif
