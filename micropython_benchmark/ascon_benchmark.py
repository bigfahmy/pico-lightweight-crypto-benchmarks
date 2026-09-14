# Ascon-AEAD128 Benchmark - MicroPython port
import time
import gc
import machine
import micropython

ITERATIONS = 100
WARMUP_RUNS = 3
CHUNK_SIZE = 4096

DATA_SIZES = [16, 256, 1024, 102400, 10485760]
SIZE_LABELS = ["16 B", "256 B", "1 KB", "100 KB", "10 MB"]

ASCON_KEY_SIZE = 16
ASCON_NONCE_SIZE = 16
ASCON_TAG_SIZE = 16
ASCON_RATE = 16
MASK64 = (1 << 64) - 1

KEY = bytes([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f])
NONCE = bytes([0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f])

# Cipher (pure Python, no hardware calls)

ASCON_IV = ((1 << 0) | (12 << 16) | (8 << 20) | (128 << 24) | (ASCON_RATE << 40))

P12_CONSTS = (0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b)
P8_CONSTS = (0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b)

def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64

def ascon_round(x, c):
    x2 = x[2] ^ c
    x0 = x[0] ^ x[4]
    x4 = x[4] ^ x[3]
    x2 ^= x[1]
    t0 = (x0 ^ (~x[1] & x2)) & MASK64
    t1 = (x[1] ^ (~x2 & x[3])) & MASK64
    t2 = (x2 ^ (~x[3] & x4)) & MASK64
    t3 = (x[3] ^ (~x4 & x0)) & MASK64
    t4 = (x4 ^ (~x0 & x[1])) & MASK64
    t1 ^= t0
    t0 ^= t4
    t3 ^= t2
    t2 = (~t2) & MASK64
    x[0] = t0 ^ ror64(t0, 19) ^ ror64(t0, 28)
    x[1] = t1 ^ ror64(t1, 61) ^ ror64(t1, 39)
    x[2] = t2 ^ ror64(t2, 1) ^ ror64(t2, 6)
    x[3] = t3 ^ ror64(t3, 10) ^ ror64(t3, 17)
    x[4] = t4 ^ ror64(t4, 7) ^ ror64(t4, 41)

def p12(x):
    for c in P12_CONSTS:
        ascon_round(x, c)

def p8(x):
    for c in P8_CONSTS:
        ascon_round(x, c)

def loadbytes(buf, offset, n):
    x = 0
    for i in range(n):
        x |= buf[offset + i] << (8 * i)
    return x

def storebytes(dst, offset, x, n):
    for i in range(n):
        dst[offset + i] = (x >> (8 * i)) & 0xFF

def pad(i):
    return 0x01 << (8 * i)

def dsep():
    return 0x80 << (8 * 7)

def clearbytes(x, n):
    for i in range(n):
        x &= ~(0xFF << (8 * i))
    return x & MASK64

def _absorb_ad(s, ad, adlen):
    if not adlen:
        return
    i = 0
    while adlen >= ASCON_RATE:
        s[0] ^= loadbytes(ad, i, 8)
        s[1] ^= loadbytes(ad, i + 8, 8)
        p8(s)
        i += ASCON_RATE
        adlen -= ASCON_RATE
    if adlen >= 8:
        s[0] ^= loadbytes(ad, i, 8)
        s[1] ^= loadbytes(ad, i + 8, adlen - 8)
        s[1] ^= pad(adlen - 8)
    else:
        s[0] ^= loadbytes(ad, i, adlen)
        s[0] ^= pad(adlen)
    s[0] &= MASK64
    s[1] &= MASK64
    p8(s)

def ascon_aead_encrypt(key, nonce, ad, plaintext, ciphertext, length):
    K0 = loadbytes(key, 0, 8)
    K1 = loadbytes(key, 8, 8)
    s = [ASCON_IV, K0, loadbytes(key, 8, 8), loadbytes(nonce, 0, 8), loadbytes(nonce, 8, 8)]
    p12(s)
    s[3] = (s[3] ^ K0) & MASK64
    s[4] = (s[4] ^ K1) & MASK64

    _absorb_ad(s, ad, len(ad))
    s[4] = (s[4] ^ dsep()) & MASK64

    i = 0
    mlen = length
    while mlen >= ASCON_RATE:
        s[0] ^= loadbytes(plaintext, i, 8)
        s[1] ^= loadbytes(plaintext, i + 8, 8)
        s[0] &= MASK64
        s[1] &= MASK64
        storebytes(ciphertext, i, s[0], 8)
        storebytes(ciphertext, i + 8, s[1], 8)
        p8(s)
        i += ASCON_RATE
        mlen -= ASCON_RATE
    if mlen >= 8:
        s[0] ^= loadbytes(plaintext, i, 8)
        s[1] ^= loadbytes(plaintext, i + 8, mlen - 8)
        s[0] &= MASK64
        s[1] &= MASK64
        storebytes(ciphertext, i, s[0], 8)
        storebytes(ciphertext, i + 8, s[1], mlen - 8)
        s[1] = (s[1] ^ pad(mlen - 8)) & MASK64
    else:
        s[0] ^= loadbytes(plaintext, i, mlen)
        s[0] &= MASK64
        storebytes(ciphertext, i, s[0], mlen)
        s[0] = (s[0] ^ pad(mlen)) & MASK64

    s[2] = (s[2] ^ K0) & MASK64
    s[3] = (s[3] ^ K1) & MASK64
    p12(s)
    s[3] = (s[3] ^ K0) & MASK64
    s[4] = (s[4] ^ K1) & MASK64

    tag = bytearray(ASCON_TAG_SIZE)
    storebytes(tag, 0, s[3], 8)
    storebytes(tag, 8, s[4], 8)
    return tag

def ascon_aead_decrypt(key, nonce, ad, ciphertext, length, tag, plaintext):
    K0 = loadbytes(key, 0, 8)
    K1 = loadbytes(key, 8, 8)
    s = [ASCON_IV, K0, K1, loadbytes(nonce, 0, 8), loadbytes(nonce, 8, 8)]
    p12(s)
    s[3] = (s[3] ^ K0) & MASK64
    s[4] = (s[4] ^ K1) & MASK64

    _absorb_ad(s, ad, len(ad))
    s[4] = (s[4] ^ dsep()) & MASK64

    i = 0
    clen = length
    while clen >= ASCON_RATE:
        c0 = loadbytes(ciphertext, i, 8)
        c1 = loadbytes(ciphertext, i + 8, 8)
        storebytes(plaintext, i, s[0] ^ c0, 8)
        storebytes(plaintext, i + 8, s[1] ^ c1, 8)
        s[0] = c0
        s[1] = c1
        p8(s)
        i += ASCON_RATE
        clen -= ASCON_RATE
    if clen >= 8:
        c0 = loadbytes(ciphertext, i, 8)
        c1 = loadbytes(ciphertext, i + 8, clen - 8)
        storebytes(plaintext, i, s[0] ^ c0, 8)
        storebytes(plaintext, i + 8, s[1] ^ c1, clen - 8)
        s[0] = c0
        s[1] = clearbytes(s[1], clen - 8)
        s[1] = (s[1] | c1) & MASK64
        s[1] = (s[1] ^ pad(clen - 8)) & MASK64
    else:
        c0 = loadbytes(ciphertext, i, clen)
        storebytes(plaintext, i, s[0] ^ c0, clen)
        s[0] = clearbytes(s[0], clen)
        s[0] = (s[0] | c0) & MASK64
        s[0] = (s[0] ^ pad(clen)) & MASK64

    s[2] = (s[2] ^ K0) & MASK64
    s[3] = (s[3] ^ K1) & MASK64
    p12(s)
    s[3] = (s[3] ^ K0) & MASK64
    s[4] = (s[4] ^ K1) & MASK64

    t = bytearray(ASCON_TAG_SIZE)
    storebytes(t, 0, s[3], 8)
    storebytes(t, 8, s[4], 8)

    result = 0
    for i in range(ASCON_TAG_SIZE):
        result |= tag[i] ^ t[i]
    return result == 0

# Benchmark harness (MicroPython / Pico specific)

plain_buf = bytearray(CHUNK_SIZE)
cipher_buf = bytearray(CHUNK_SIZE)
recov_buf = bytearray(CHUNK_SIZE)
tag_buf = bytearray(ASCON_TAG_SIZE)
enc_samples = [0] * ITERATIONS
dec_samples = [0] * ITERATIONS

temp_sensor = machine.ADC(4)

def read_temp():
    reading = temp_sensor.read_u16() * (3.3 / 65535)
    return 27.0 - (reading - 0.706) / 0.001721

def verify_ascon():
    pt = bytes([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10])
    ct = bytearray(16)
    dec = bytearray(16)
    tag = ascon_aead_encrypt(KEY, NONCE, b"", pt, ct, len(pt))
    ok = ascon_aead_decrypt(KEY, NONCE, b"", ct, len(ct), tag, dec)
    return ok and bytes(dec) == pt

def compute_stats(samples, n):
    mean = sum(samples[:n]) // n
    return mean, min(samples[:n]), max(samples[:n])

def encrypt_data(data_size):
    global tag_buf
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        tag_buf = ascon_aead_encrypt(KEY, NONCE, b"", plain_buf, cipher_buf, blk)
        remaining -= blk

def decrypt_data(data_size):
    remaining = data_size
    while remaining > 0:
        blk = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
        ascon_aead_decrypt(KEY, NONCE, b"", cipher_buf, blk, tag_buf, recov_buf)
        remaining -= blk

def run_benchmark(data_size, label):
    for i in range(CHUNK_SIZE):
        plain_buf[i] = i & 0xFF

    gc.collect()
    heap_before = gc.mem_free()

    for _ in range(WARMUP_RUNS):
        encrypt_data(data_size)

    stack_before = micropython.stack_use()

    for it in range(ITERATIONS):
        t0 = time.ticks_us()
        encrypt_data(data_size)
        enc_samples[it] = time.ticks_diff(time.ticks_us(), t0)

    stack_used = micropython.stack_use() - stack_before
    gc.collect()
    heap_after = gc.mem_free()
    temp = read_temp()

    encrypt_data(data_size)
    for it in range(ITERATIONS):
        t0 = time.ticks_us()
        decrypt_data(data_size)
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
    print("  Ascon-AEAD128 Benchmark (MicroPython)")
    print("  Raspberry Pi Pico W")
    print("  Iterations: {} | Chunk: {} bytes".format(ITERATIONS, CHUNK_SIZE))
    print("========================================")

    print("\n[1] Verifying Ascon-AEAD128 correctness (encrypt/decrypt + tag)...")
    if not verify_ascon():
        print("  [FAIL] Aborting.")
        while True:
            pass
    print("  [PASS] Verified.")

    print("\n[2] Starting benchmarks...")
    print("  Have UM24C ready to note Watts for each test.\n")

    for size, label in zip(DATA_SIZES, SIZE_LABELS):
        run_benchmark(size, label)

    print("\n========================================")
    print("  Benchmark Complete!")
    print("========================================")

if __name__ == "__main__":
    main()
