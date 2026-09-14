#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/adc.h"
#include "ascon.h"

#define ITERATIONS   100
#define WARMUP_RUNS  3
#define NUM_SIZES    5
#define CHUNK_SIZE   4096

static const size_t DATA_SIZES[NUM_SIZES] = {
    16, 256, 1024, 102400, 10485760
};
static const char *SIZE_LABELS[NUM_SIZES] = {
    "16 B", "256 B", "1 KB", "100 KB", "10 MB"
};

static const uint8_t KEY[ASCON_KEY_SIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t NONCE[ASCON_NONCE_SIZE] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static uint8_t plain_buf[CHUNK_SIZE];
static uint8_t cipher_buf[CHUNK_SIZE];
static uint8_t recov_buf[CHUNK_SIZE];
static uint8_t tag_buf[ASCON_TAG_SIZE];
static uint64_t enc_samples[ITERATIONS];
static uint64_t dec_samples[ITERATIONS];

// Stack painting for RAM measurement
#define STACK_PAINT_SIZE 2048
#define STACK_SENTINEL   0xAB
static uint8_t stack_paint[STACK_PAINT_SIZE];

static void paint_stack() {
    memset(stack_paint, STACK_SENTINEL, STACK_PAINT_SIZE);
}

static uint32_t measure_stack() {
    uint32_t used = 0;
    for (uint32_t i = 0; i < STACK_PAINT_SIZE; i++) {
        if (stack_paint[i] != STACK_SENTINEL) used = i + 1;
    }
    return used;
}

// Measure free heap by trying allocations
static uint32_t measure_free_heap() {
    void *p = malloc(1);
    free(p);
    uint32_t free_mem = 0;
    uint32_t test = 512;
    while (test > 0) {
        void *ptr = malloc(test);
        if (ptr) {
            free_mem += test;
            free(ptr);
        }
        test /= 2;
    }
    return free_mem;
}

// Read Pico internal temperature
static float read_temp() {
    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(4);
    uint16_t raw = adc_read();
    float voltage = raw * 3.3f / 4096.0f;
    return 27.0f - (voltage - 0.706f) / 0.001721f;
}

// Round-trip self-test: encrypt a small message under (KEY, NONCE), decrypt it
// back and confirm both the plaintext and the authentication tag check out.
static bool verify_ascon() {
    uint8_t pt[16]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    uint8_t ct[16]  = {0};
    uint8_t tag[ASCON_TAG_SIZE] = {0};
    uint8_t dec[16] = {0};

    ascon_aead_encrypt(KEY, NONCE, nullptr, 0, pt, sizeof(pt), ct, tag);
    int ok = ascon_aead_decrypt(KEY, NONCE, nullptr, 0, ct, sizeof(ct), tag, dec);

    return ok == 0 && memcmp(pt, dec, sizeof(pt)) == 0;
}

static uint64_t compute_mean(uint64_t *s, int n) {
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) sum += s[i];
    return sum / n;
}

static uint64_t compute_min(uint64_t *s, int n) {
    uint64_t m = s[0];
    for (int i = 1; i < n; i++) if (s[i] < m) m = s[i];
    return m;
}

static uint64_t compute_max(uint64_t *s, int n) {
    uint64_t m = s[0];
    for (int i = 1; i < n; i++) if (s[i] > m) m = s[i];
    return m;
}

static void encrypt_data(size_t data_size) {
    size_t remaining = data_size;
    while (remaining > 0) {
        size_t blk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        ascon_aead_encrypt(KEY, NONCE, nullptr, 0, plain_buf, blk, cipher_buf, tag_buf);
        remaining -= blk;
    }
}

static void decrypt_data(size_t data_size) {
    size_t remaining = data_size;
    while (remaining > 0) {
        size_t blk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        ascon_aead_decrypt(KEY, NONCE, nullptr, 0, cipher_buf, blk, tag_buf, recov_buf);
        remaining -= blk;
    }
}

static void run_benchmark(size_t data_size, const char *label) {
    for (int i = 0; i < CHUNK_SIZE; i++)
        plain_buf[i] = (uint8_t)(i & 0xFF);

    uint32_t heap_before = measure_free_heap();

    for (int w = 0; w < WARMUP_RUNS; w++)
        encrypt_data(data_size);

    paint_stack();

    for (int iter = 0; iter < ITERATIONS; iter++) {
        uint64_t t0 = time_us_64();
        encrypt_data(data_size);
        enc_samples[iter] = time_us_64() - t0;
    }

    uint32_t stack_used = measure_stack();
    uint32_t heap_after = measure_free_heap();
    float temp = read_temp();

    encrypt_data(data_size);
    for (int iter = 0; iter < ITERATIONS; iter++) {
        uint64_t t0 = time_us_64();
        decrypt_data(data_size);
        dec_samples[iter] = time_us_64() - t0;
    }

    uint64_t enc_mean = compute_mean(enc_samples, ITERATIONS);
    uint64_t enc_min  = compute_min(enc_samples, ITERATIONS);
    uint64_t enc_max  = compute_max(enc_samples, ITERATIONS);
    uint64_t dec_mean = compute_mean(dec_samples, ITERATIONS);
    uint64_t dec_min  = compute_min(dec_samples, ITERATIONS);
    uint64_t dec_max  = compute_max(dec_samples, ITERATIONS);

    double enc_kbps = (enc_mean > 0) ?
        ((double)data_size / 1024.0) / ((double)enc_mean / 1000000.0) : 0;
    double dec_kbps = (dec_mean > 0) ?
        ((double)data_size / 1024.0) / ((double)dec_mean / 1000000.0) : 0;

    printf("\n--- Data Size: %s ---\n", label);
    printf("      Record UM24C Watts reading now    \n");
    printf("  Encrypt | Mean: %llu us | Min: %llu us | Max: %llu us\n",
           enc_mean, enc_min, enc_max);
    printf("  Decrypt | Mean: %llu us | Min: %llu us | Max: %llu us\n",
           dec_mean, dec_min, dec_max);
    printf("  Throughput Encrypt: %.2f KB/s\n", enc_kbps);
    printf("  Throughput Decrypt: %.2f KB/s\n", dec_kbps);
    printf("  Stack usage: %u bytes\n", (unsigned)stack_used);
    printf("  Free heap before: %u bytes\n", (unsigned)heap_before);
    printf("  Free heap after:  %u bytes\n", (unsigned)heap_after);
    printf("  Pico temperature: %.1f C\n", temp);

    sleep_ms(5000);
}

int main() {
    stdio_init_all();
    sleep_ms(10000);

    printf("\n========================================\n");
    printf("  Ascon-AEAD128 Benchmark\n");
    printf("  Raspberry Pi Pico W\n");
    printf("  Iterations: %d | Chunk: %d bytes\n", ITERATIONS, CHUNK_SIZE);
    printf("========================================\n");

    printf("\n[1] Verifying Ascon-AEAD128 correctness (encrypt/decrypt + tag)...\n");
    if (!verify_ascon()) {
        printf("  [FAIL] Aborting.\n");
        while (1);
    }
    printf("  [PASS] Verified.\n");

    printf("\n[2] Starting benchmarks...\n");
    printf("  Have UM24C ready to note Watts for each test.\n\n");

    for (int i = 0; i < NUM_SIZES; i++) {
        run_benchmark(DATA_SIZES[i], SIZE_LABELS[i]);
    }

    printf("\n========================================\n");
    printf("  Benchmark Complete!\n");
    printf("========================================\n");

    while (1);
    return 0;
}
