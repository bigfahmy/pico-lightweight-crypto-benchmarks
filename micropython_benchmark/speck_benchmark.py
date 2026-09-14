# SPECK 64/128 CBC Benchmark - MicroPython port
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

SPECK_ROUNDS = 27
SPECK_BLOCK_SIZE = 8
MASK32 = 0xFFFFFFFF

KEY = (0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918)
IV = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

# Cipher (pure Python, no hardware calls)

def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK32

def ror32(x, r):
    return ((x >> r) | (x << (32 - r))) & MASK32

def speck_key_schedule(key):
    a = key[0]
    b = [key[1], key[2], key[3]]
    round_keys = [0] * SPECK_ROUNDS
    round_keys[0] = a
    for i in range(SPECK_ROUNDS - 1):
        idx = i % 3
        b[idx] = ((ror32(b[idx], 8) + a) & MASK32) ^ i
        a = rol32(a, 3) ^ b[idx]
        round_keys[i + 1] = a
    return round_keys

def speck_encrypt_block(rk, x, y):
    for i in range(SPECK_ROUNDS):
        x = ((ror32(x, 8) + y) & MASK32) ^ rk[i]
        y = rol32(y, 3) ^ x
    return x, y

def speck_decrypt_block(rk, x, y):
    for i in range(SPECK_ROUNDS - 1, -1, -1):
        y = ror32(x ^ y, 3)
        x = rol32(((x ^ rk[i]) - y) & MASK32, 8)
    return x, y

def speck_cbc_encrypt(rk, iv, src, dst, length):
    p0, p1, p2, p3, p4, p5, p6, p7 = iv
    for i in range(0, length, SPECK_BLOCK_SIZE):
        x, y = struct.unpack_from('<2I', src, i)
        x ^= p0 | (p1 << 8) | (p2 << 16) | (p3 << 24)
        y ^= p4 | (p5 << 8) | (p6 << 16) | (p7 << 24)
        cx, cy = speck_encrypt_block(rk, x & MASK32, y & MASK32)
        struct.pack_into('<2I', dst, i, cx, cy)
        p0, p1, p2, p3, p4, p5, p6, p7 = dst[i:i + 8]

def speck_cbc_decrypt(rk, iv, src, dst, length):
    p0, p1, p2, p3, p4, p5, p6, p7 = iv
    for i in range(0, length, SPECK_BLOCK_SIZE):
        cx, cy = struct.unpack_from('<2I', src, i)
        px, py = speck_decrypt_block(rk, cx, cy)
        px ^= p0 | (p1 << 8) | (p2 << 16) | (p3 << 24)
        py ^= p4 | (p5 << 8) | (p6 << 16) | (p7 << 24)
        struct.pack_into('<2I', dst, i, px & MASK32, py & MASK32)
        p0, p1, p2, p3, p4, p5, p6, p7 = src[i:i + 8]

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

def verify_speck(rk):
    pt = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    ct = bytearray(8)
    dec = bytearray(8)
    speck_cbc_encrypt(rk, IV, pt, ct, 8)
    speck_cbc_decrypt(rk, IV, ct, dec, 8)
    return bytes(dec) == pt

def compute_stats(samples, n):
    mean = sum(samples[:n]) // n
    return mean, min(samples[:n]), max(samples[:n])

def encrypt_data(rk, data_size):
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        blk = (blk // SPECK_BLOCK_SIZE) * SPECK_BLOCK_SIZE
        if blk == 0:
            break
        speck_cbc_encrypt(rk, IV, plain_buf, cipher_buf, blk)
        remaining -= blk

def decrypt_data(rk, data_size):
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        blk = (blk // SPECK_BLOCK_SIZE) * SPECK_BLOCK_SIZE
        if blk == 0:
            break
        speck_cbc_decrypt(rk, IV, cipher_buf, recov_buf, blk)
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
    print("  SPECK 64/128 CBC Benchmark (MicroPython)")
    print("  Raspberry Pi Pico W")
    print("  Iterations: {} | Chunk: {} bytes".format(ITERATIONS, CHUNK_SIZE))
    print("========================================")

    round_keys = speck_key_schedule(KEY)

    print("\n[1] Verifying SPECK correctness...")
    if not verify_speck(round_keys):
        print("  [FAIL] Aborting.")
        while True:
            pass
    print("  [PASS] Verified.")

    print("\n[2] Starting benchmarks...")
    print("  Have UM24C ready to note Watts for each test.\n")

    for size, label in zip(DATA_SIZES, SIZE_LABELS):
        run_benchmark(round_keys, size, label)

    print("\n========================================")
    print("  Benchmark Complete!")
    print("========================================")

if __name__ == "__main__":
    main()
