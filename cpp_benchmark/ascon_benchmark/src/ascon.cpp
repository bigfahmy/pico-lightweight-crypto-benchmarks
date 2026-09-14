#include "ascon.h"
#include <string.h>

typedef struct {
    uint64_t x[5];
} ascon_state_t;

#define ASCON_AEAD_VARIANT   1
#define ASCON_PA_ROUNDS      12
#define ASCON_PB_ROUNDS      8
#define ASCON_TAG_BITS       (ASCON_TAG_SIZE * 8)

#define ASCON_IV \
    (((uint64_t)(ASCON_AEAD_VARIANT) << 0) | \
     ((uint64_t)(ASCON_PA_ROUNDS) << 16) | \
     ((uint64_t)(ASCON_PB_ROUNDS) << 20) | \
     ((uint64_t)(ASCON_TAG_BITS) << 24) | \
     ((uint64_t)(ASCON_RATE) << 40))

static inline uint64_t ROR(uint64_t x, int n) {
    return x >> n | x << (-n & 63);
}

static inline void ROUND(ascon_state_t *s, uint8_t C) {
    ascon_state_t t;
    s->x[2] ^= C;
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];
    s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}

static inline void P12(ascon_state_t *s) {
    ROUND(s, 0xf0); ROUND(s, 0xe1); ROUND(s, 0xd2); ROUND(s, 0xc3);
    ROUND(s, 0xb4); ROUND(s, 0xa5); ROUND(s, 0x96); ROUND(s, 0x87);
    ROUND(s, 0x78); ROUND(s, 0x69); ROUND(s, 0x5a); ROUND(s, 0x4b);
}

static inline void P8(ascon_state_t *s) {
    ROUND(s, 0xb4); ROUND(s, 0xa5); ROUND(s, 0x96); ROUND(s, 0x87);
    ROUND(s, 0x78); ROUND(s, 0x69); ROUND(s, 0x5a); ROUND(s, 0x4b);
}

#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (8 * (i))))
#define SETBYTE(b, i) ((uint64_t)(b) << (8 * (i)))
#define PAD(i) SETBYTE(0x01, i)
#define DSEP() SETBYTE(0x80, 7)

static inline uint64_t LOADBYTES(const uint8_t *bytes, int n) {
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
    return x;
}

static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n) {
    for (int i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

static inline uint64_t CLEARBYTES(uint64_t x, int n) {
    for (int i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
    return x;
}

void ascon_aead_encrypt(const uint8_t key[ASCON_KEY_SIZE],
                         const uint8_t nonce[ASCON_NONCE_SIZE],
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *plaintext, size_t len,
                         uint8_t *ciphertext, uint8_t tag[ASCON_TAG_SIZE]) {
    const uint64_t K0 = LOADBYTES(key, 8);
    const uint64_t K1 = LOADBYTES(key + 8, 8);
    const uint64_t N0 = LOADBYTES(nonce, 8);
    const uint64_t N1 = LOADBYTES(nonce + 8, 8);

    ascon_state_t s;
    s.x[0] = ASCON_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    if (adlen) {
        while (adlen >= ASCON_RATE) {
            s.x[0] ^= LOADBYTES(ad, 8);
            s.x[1] ^= LOADBYTES(ad + 8, 8);
            P8(&s);
            ad += ASCON_RATE;
            adlen -= ASCON_RATE;
        }
        if (adlen >= 8) {
            s.x[0] ^= LOADBYTES(ad, 8);
            s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
            s.x[1] ^= PAD(adlen - 8);
        } else {
            s.x[0] ^= LOADBYTES(ad, adlen);
            s.x[0] ^= PAD(adlen);
        }
        P8(&s);
    }
    s.x[4] ^= DSEP();

    while (len >= ASCON_RATE) {
        s.x[0] ^= LOADBYTES(plaintext, 8);
        s.x[1] ^= LOADBYTES(plaintext + 8, 8);
        STOREBYTES(ciphertext, s.x[0], 8);
        STOREBYTES(ciphertext + 8, s.x[1], 8);
        P8(&s);
        plaintext += ASCON_RATE;
        ciphertext += ASCON_RATE;
        len -= ASCON_RATE;
    }
    if (len >= 8) {
        s.x[0] ^= LOADBYTES(plaintext, 8);
        s.x[1] ^= LOADBYTES(plaintext + 8, len - 8);
        STOREBYTES(ciphertext, s.x[0], 8);
        STOREBYTES(ciphertext + 8, s.x[1], len - 8);
        s.x[1] ^= PAD(len - 8);
    } else {
        s.x[0] ^= LOADBYTES(plaintext, len);
        STOREBYTES(ciphertext, s.x[0], len);
        s.x[0] ^= PAD(len);
    }

    s.x[2] ^= K0;
    s.x[3] ^= K1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    STOREBYTES(tag, s.x[3], 8);
    STOREBYTES(tag + 8, s.x[4], 8);
}

int ascon_aead_decrypt(const uint8_t key[ASCON_KEY_SIZE],
                        const uint8_t nonce[ASCON_NONCE_SIZE],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *ciphertext, size_t len,
                        const uint8_t tag[ASCON_TAG_SIZE],
                        uint8_t *plaintext) {
    const uint64_t K0 = LOADBYTES(key, 8);
    const uint64_t K1 = LOADBYTES(key + 8, 8);
    const uint64_t N0 = LOADBYTES(nonce, 8);
    const uint64_t N1 = LOADBYTES(nonce + 8, 8);

    ascon_state_t s;
    s.x[0] = ASCON_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    if (adlen) {
        while (adlen >= ASCON_RATE) {
            s.x[0] ^= LOADBYTES(ad, 8);
            s.x[1] ^= LOADBYTES(ad + 8, 8);
            P8(&s);
            ad += ASCON_RATE;
            adlen -= ASCON_RATE;
        }
        if (adlen >= 8) {
            s.x[0] ^= LOADBYTES(ad, 8);
            s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
            s.x[1] ^= PAD(adlen - 8);
        } else {
            s.x[0] ^= LOADBYTES(ad, adlen);
            s.x[0] ^= PAD(adlen);
        }
        P8(&s);
    }
    s.x[4] ^= DSEP();

    while (len >= ASCON_RATE) {
        uint64_t c0 = LOADBYTES(ciphertext, 8);
        uint64_t c1 = LOADBYTES(ciphertext + 8, 8);
        STOREBYTES(plaintext, s.x[0] ^ c0, 8);
        STOREBYTES(plaintext + 8, s.x[1] ^ c1, 8);
        s.x[0] = c0;
        s.x[1] = c1;
        P8(&s);
        plaintext += ASCON_RATE;
        ciphertext += ASCON_RATE;
        len -= ASCON_RATE;
    }
    if (len >= 8) {
        uint64_t c0 = LOADBYTES(ciphertext, 8);
        uint64_t c1 = LOADBYTES(ciphertext + 8, len - 8);
        STOREBYTES(plaintext, s.x[0] ^ c0, 8);
        STOREBYTES(plaintext + 8, s.x[1] ^ c1, len - 8);
        s.x[0] = c0;
        s.x[1] = CLEARBYTES(s.x[1], len - 8);
        s.x[1] |= c1;
        s.x[1] ^= PAD(len - 8);
    } else {
        uint64_t c0 = LOADBYTES(ciphertext, len);
        STOREBYTES(plaintext, s.x[0] ^ c0, len);
        s.x[0] = CLEARBYTES(s.x[0], len);
        s.x[0] |= c0;
        s.x[0] ^= PAD(len);
    }

    s.x[2] ^= K0;
    s.x[3] ^= K1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    uint8_t t[ASCON_TAG_SIZE];
    STOREBYTES(t, s.x[3], 8);
    STOREBYTES(t + 8, s.x[4], 8);

    uint8_t result = 0;
    for (int i = 0; i < ASCON_TAG_SIZE; ++i) result |= tag[i] ^ t[i];
    return result == 0 ? 0 : -1;
}
