# PRESENT-80 CBC Benchmark - MicroPython port
import time
import gc
import struct
import machine
import micropython

ITERATIONS = 100
WARMUP_RUNS = 3
CHUNK_SIZE = 4096

DATA_SIZES = [16, 256, 1024, 102400, 10485760]
SIZE_LABELS = ["16 B", "256 B", "1 KB", "100 KB", "10 MB"]

PRESENT_ROUNDS = 31
PRESENT_BLOCK_SIZE = 8
MASK64 = (1 << 64) - 1

KEY = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])
IV = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

# Cipher (pure Python, no hardware calls)

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
INV_SBOX = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]
P_TABLE = [
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
]
INV_P_TABLE = [0] * 64
for _i in range(64):
    INV_P_TABLE[P_TABLE[_i]] = _i

def sbox_layer(state, sbox):
    result = 0
    for i in range(16):
        nibble = (state >> (4 * i)) & 0xF
        result |= sbox[nibble] << (4 * i)
    return result

def permute_table(source, table):
    result = 0
    for i in range(64):
        bit = (source >> (63 - i)) & 1
        result |= bit << (63 - table[i])
    return result

def present_key_schedule(key):
    key_high = struct.unpack('>Q', key[0:8])[0]
    key_low = (key[8] << 8) | key[9]

    round_keys = [0] * (PRESENT_ROUNDS + 1)
    round_keys[0] = key_high
    for i in range(1, PRESENT_ROUNDS + 1):
        temp1 = key_high
        temp2 = key_low

        key_high = ((key_high << 61) | (temp2 << 45) | (temp1 >> 19)) & MASK64
        key_low = (temp1 >> 3) & 0xFFFF

        top_nibble = (key_high >> 60) & 0xF
        key_high = (key_high & 0x0FFFFFFFFFFFFFFF) | (SBOX[top_nibble] << 60)

        key_low ^= (i & 1) << 15
        key_high = (key_high ^ (i >> 1)) & MASK64

        round_keys[i] = key_high
    return round_keys

def present_encrypt_block(rk, pt):
    state = pt
    for i in range(PRESENT_ROUNDS):
        state ^= rk[i]
        state = sbox_layer(state, SBOX)
        state = permute_table(state, P_TABLE)
    return (state ^ rk[PRESENT_ROUNDS]) & MASK64

def present_decrypt_block(rk, ct):
    state = ct ^ rk[PRESENT_ROUNDS]
    for i in range(PRESENT_ROUNDS - 1, -1, -1):
        state = permute_table(state, INV_P_TABLE)
        state = sbox_layer(state, INV_SBOX)
        state ^= rk[i]
    return state & MASK64

def present_cbc_encrypt(rk, iv, src, dst, length):
    prev = struct.unpack('>Q', iv)[0]
    for i in range(0, length, PRESENT_BLOCK_SIZE):
        pt = struct.unpack_from('>Q', src, i)[0] ^ prev
        ct = present_encrypt_block(rk, pt)
        struct.pack_into('>Q', dst, i, ct)
        prev = ct

def present_cbc_decrypt(rk, iv, src, dst, length):
    prev = struct.unpack('>Q', iv)[0]
    for i in range(0, length, PRESENT_BLOCK_SIZE):
        ct = struct.unpack_from('>Q', src, i)[0]
        pt = present_decrypt_block(rk, ct) ^ prev
        struct.pack_into('>Q', dst, i, pt)
        prev = ct

# Benchmark harness (MicroPython / Pico specific)

plain_buf = bytearray(CHUNK_SIZE)
cipher_buf = bytearray(CHUNK_SIZE)
recov_buf = bytearray(CHUNK_SIZE)
enc_samples = [0] * ITERATIONS
dec_samples = [0] * ITERATIONS

temp_sensor = machine.ADC(4)

def read_temp():
    reading = temp_sensor.read_u16() * (3.3 / 65535)
    return 27.0 - (reading - 0.706) / 0.001721

def verify_present_kat():
    zero_key = bytes(10)
    rk = present_key_schedule(zero_key)
    ct = present_encrypt_block(rk, 0)
    return ct == 0x5579c1387b228445

def verify_present(rk):
    pt = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    ct = bytearray(8)
    dec = bytearray(8)
    present_cbc_encrypt(rk, IV, pt, ct, 8)
    present_cbc_decrypt(rk, IV, ct, dec, 8)
    return bytes(dec) == bytes(pt)

def compute_stats(samples, n):
    mean = sum(samples[:n]) // n
    return mean, min(samples[:n]), max(samples[:n])

def encrypt_data(rk, data_size):
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        blk = (blk // PRESENT_BLOCK_SIZE) * PRESENT_BLOCK_SIZE
        if blk == 0:
            break
        present_cbc_encrypt(rk, IV, plain_buf, cipher_buf, blk)
        remaining -= blk

def decrypt_data(rk, data_size):
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        blk = (blk // PRESENT_BLOCK_SIZE) * PRESENT_BLOCK_SIZE
        if blk == 0:
            break
        present_cbc_decrypt(rk, IV, cipher_buf, recov_buf, blk)
        remaining -= blk

def run_benchmark(rk, data_size, label):
    for i in range(CHUNK_SIZE):
        plain_buf[i] = i & 0xFF

    gc.collect()
    heap_before = gc.mem_free()

    for _ in range(WARMUP_RUNS):
        encrypt_data(rk, data_size)

    stack_before = micropython.stack_use()

    for it in range(ITERATIONS):
        t0 = time.ticks_us()
        encrypt_data(rk, data_size)
        enc_samples[it] = time.ticks_diff(time.ticks_us(), t0)

    stack_used = micropython.stack_use() - stack_before
    gc.collect()
    heap_after = gc.mem_free()
    temp = read_temp()

    encrypt_data(rk, data_size)
    for it in range(ITERATIONS):
        t0 = time.ticks_us()
        decrypt_data(rk, data_size)
        dec_samples[it] = time.ticks_diff(time.ticks_us(), t0)

    enc_mean, enc_min, enc_max = compute_stats(enc_samples, ITERATIONS)
    dec_mean, dec_min, dec_max = compute_stats(dec_samples, ITERATIONS)

    enc_kbps = (data_size / 1024.0) / (enc_mean / 1000000.0) if enc_mean > 0 else 0
    dec_kbps = (data_size / 1024.0) / (dec_mean / 1000000.0) if dec_mean > 0 else 0

    print("\n--- Data Size: {} ---".format(label))
    print("      Record UM24C Watts reading now    ")
    print("  Encrypt | Mean: {} us | Min: {} us | Max: {} us".format(enc_mean, enc_min, enc_max))
    print("  Decrypt | Mean: {} us | Min: {} us | Max: {} us".format(dec_mean, dec_min, dec_max))
    print("  Throughput Encrypt: {:.2f} KB/s".format(enc_kbps))
    print("  Throughput Decrypt: {:.2f} KB/s".format(dec_kbps))
    print("  Stack usage (delta): {} bytes".format(stack_used))
    print("  Free heap before: {} bytes".format(heap_before))
    print("  Free heap after:  {} bytes".format(heap_after))
    print("  Pico temperature: {:.1f} C".format(temp))

    time.sleep(5)

def main():
    time.sleep(10)

    print("\n========================================")
    print("  PRESENT-80 CBC Benchmark (MicroPython)")
    print("  Raspberry Pi Pico W")
    print("  Iterations: {} | Chunk: {} bytes".format(ITERATIONS, CHUNK_SIZE))
    print("========================================")

    print("\n[1] Verifying PRESENT-80 known-answer test vector...")
    if not verify_present_kat():
        print("  [FAIL] Aborting.")
        while True:
            pass
    print("  [PASS] Matches official test vector.")

    round_keys = present_key_schedule(KEY)

    print("\n[2] Verifying CBC round-trip correctness...")
    if not verify_present(round_keys):
        print("  [FAIL] Aborting.")
        while True:
            pass
    print("  [PASS] Verified.")

    print("\n[3] Starting benchmarks...")
    print("  Have UM24C ready to note Watts for each test.\n")

    for size, label in zip(DATA_SIZES, SIZE_LABELS):
        run_benchmark(round_keys, size, label)

    print("\n========================================")
    print("  Benchmark Complete!")
    print("========================================")

if __name__ == "__main__":
    main()
