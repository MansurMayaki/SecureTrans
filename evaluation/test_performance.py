# ============================================================
# SecureTrans - Sprint 6: Performance Benchmarking
# Measures encryption overhead across file sizes
# ============================================================

import os
import sys
import time
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from crypto.aes_module import aes_encrypt, aes_decrypt
from crypto.pfs_module import generate_session_key, destroy_session_key
from crypto.rsa_module import (
    generate_rsa_keypair, export_public_key,
    rsa_encrypt, rsa_decrypt
)
from crypto.integrity_module import compute_hash

print("=" * 60)
print("   SecureTrans — Performance Benchmarking")
print("=" * 60)
print(f"\n{'Size':<12} {'Hash(ms)':<12} {'AES Enc(ms)':<14}"
      f"{'AES Dec(ms)':<14} {'RSA(ms)':<12} {'Total(ms)':<12}")
print("-" * 76)

FILE_SIZES_MB = [1, 10, 50, 100]

results = []

for size_mb in FILE_SIZES_MB:
    size_bytes = size_mb * 1024 * 1024
    file_data  = os.urandom(size_bytes)

    # ── SHA-256 Hash ──────────────────────────────────────────
    t0 = time.perf_counter()
    file_hash = compute_hash(file_data)
    hash_ms = (time.perf_counter() - t0) * 1000

    # ── AES-256-GCM Encryption ────────────────────────────────
    key = generate_session_key()
    t0 = time.perf_counter()
    ciphertext, iv, tag = aes_encrypt(key, file_data)
    enc_ms = (time.perf_counter() - t0) * 1000

    # ── AES-256-GCM Decryption ────────────────────────────────
    t0 = time.perf_counter()
    decrypted = aes_decrypt(key, ciphertext, iv, tag)
    dec_ms = (time.perf_counter() - t0) * 1000

    # ── RSA Key Exchange ──────────────────────────────────────
    receiver_key = generate_rsa_keypair()
    receiver_pub = export_public_key(receiver_key)
    t0 = time.perf_counter()
    enc_key = rsa_encrypt(receiver_pub, key)
    rsa_decrypt(receiver_key, enc_key)
    rsa_ms = (time.perf_counter() - t0) * 1000

    total_ms = hash_ms + enc_ms + dec_ms + rsa_ms

    print(f"{str(size_mb) + ' MB':<12} "
          f"{hash_ms:<12.1f} "
          f"{enc_ms:<14.1f} "
          f"{dec_ms:<14.1f} "
          f"{rsa_ms:<12.1f} "
          f"{total_ms:<12.1f}")

    results.append({
        'size_mb' : size_mb,
        'total_ms': total_ms
    })

    destroy_session_key(key)

print("-" * 76)

# ── Overhead Analysis ─────────────────────────────────────────
print("\n[ANALYSIS] Cryptographic Overhead vs Transfer Time")
print(f"  (Assuming 100 Mbps LAN = 12.5 MB/s transfer speed)\n")

for r in results:
    transfer_ms = (r['size_mb'] / 12.5) * 1000
    overhead_pct = (r['total_ms'] / (r['total_ms'] + transfer_ms)) * 100
    status = "✓ Within 5% target" if overhead_pct < 5 else "⚠ Exceeds 5%"
    print(f"  {r['size_mb']:>3} MB — "
          f"Crypto: {r['total_ms']:.0f}ms | "
          f"Transfer: {transfer_ms:.0f}ms | "
          f"Overhead: {overhead_pct:.1f}% {status}")

print("\n" + "=" * 60)
print("   Performance Benchmarking Complete")
print("   Results ready for inclusion in evaluation report")
print("=" * 60)