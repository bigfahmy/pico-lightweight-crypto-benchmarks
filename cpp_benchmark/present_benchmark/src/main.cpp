#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/adc.h"
#include "present.h"

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

static const uint8_t KEY[PRESENT_KEY_SIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
};
static const uint8_t IV[PRESENT_BLOCK_SIZE] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
};

static uint8_t plain_buf[CHUNK_SIZE];
static uint8_t cipher_buf[CHUNK_SIZE];
static uint8_t recov_buf[CHUNK_SIZE];
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

// zero key + zero plaintext should give 0x5579c1387b228445, known test vector
static bool verify_present_kat() {
    uint8_t zero_key[PRESENT_KEY_SIZE] = {0};
    uint64_t rk[PRESENT_ROUNDS + 1];
    present_key_schedule(zero_key, rk);
    uint64_t ct = present_encrypt_block(rk, 0x0000000000000000ULL);
    return ct == 0x5579c1387b228445ULL;
}

static bool verify_present(const uint64_t rk[PRESENT_ROUNDS + 1]) {
    uint8_t pt[PRESENT_BLOCK_SIZE]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    uint8_t ct[PRESENT_BLOCK_SIZE]  = {0};
    uint8_t dec[PRESENT_BLOCK_SIZE] = {0};
    present_cbc_encrypt(rk, IV, pt, ct, PRESENT_BLOCK_SIZE);
    present_cbc_decrypt(rk, IV, ct, dec, PRESENT_BLOCK_SIZE);
    return memcmp(pt, dec, PRESENT_BLOCK_SIZE) == 0;
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

static void encrypt_data(const uint64_t rk[PRESENT_ROUNDS + 1], size_t data_size) {
    size_t remaining = data_size;
    while (remaining > 0) {
        size_t blk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        blk = (blk / PRESENT_BLOCK_SIZE) * PRESENT_BLOCK_SIZE;
        if (blk == 0) break;
        present_cbc_encrypt(rk, IV, plain_buf, cipher_buf, blk);
        remaining -= blk;
    }
}

static void decrypt_data(const uint64_t rk[PRESENT_ROUNDS + 1], size_t data_size) {
    size_t remaining = data_size;
    while (remaining > 0) {
        size_t blk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        blk = (blk / PRESENT_BLOCK_SIZE) * PRESENT_BLOCK_SIZE;
        if (blk == 0) break;
        present_cbc_decrypt(rk, IV, cipher_buf, recov_buf, blk);
        remaining -= blk;
    }
}

static void run_benchmark(const uint64_t rk[PRESENT_ROUNDS + 1],
                           size_t data_size, const char *label) {
    for (int i = 0; i < CHUNK_SIZE; i++)
        plain_buf[i] = (uint8_t)(i & 0xFF);

    uint32_t heap_before = measure_free_heap();

    for (int w = 0; w < WARMUP_RUNS; w++)
        encrypt_data(rk, data_size);

    paint_stack();

    for (int iter = 0; iter < ITERATIONS; iter++) {
        uint64_t t0 = time_us_64();
        encrypt_data(rk, data_size);
        enc_samples[iter] = time_us_64() - t0;
    }

    uint32_t stack_used = measure_stack();
    uint32_t heap_after = measure_free_heap();
    float temp = read_temp();

    encrypt_data(rk, data_size);
    for (int iter = 0; iter < ITERATIONS; iter++) {
        uint64_t t0 = time_us_64();
        decrypt_data(rk, data_size);
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
    printf("  PRESENT-80 CBC Benchmark\n");
    printf("  Raspberry Pi Pico W\n");
    printf("  Iterations: %d | Chunk: %d bytes\n", ITERATIONS, CHUNK_SIZE);
    printf("========================================\n");

    printf("\n[1] Verifying PRESENT-80 known-answer test vector...\n");
    if (!verify_present_kat()) {
        printf("  [FAIL] Aborting.\n");
        while (1);
    }
    printf("  [PASS] Matches official test vector.\n");

    uint64_t round_keys[PRESENT_ROUNDS + 1];
    present_key_schedule(KEY, round_keys);

    printf("\n[2] Verifying CBC round-trip correctness...\n");
    if (!verify_present(round_keys)) {
        printf("  [FAIL] Aborting.\n");
        while (1);
    }
    printf("  [PASS] Verified.\n");

    printf("\n[3] Starting benchmarks...\n");
    printf("  Have UM24C ready to note Watts for each test.\n\n");

    for (int i = 0; i < NUM_SIZES; i++) {
        run_benchmark(round_keys, DATA_SIZES[i], SIZE_LABELS[i]);
    }

    printf("\n========================================\n");
    printf("  Benchmark Complete!\n");
    printf("========================================\n");

    while (1);
    return 0;
}
