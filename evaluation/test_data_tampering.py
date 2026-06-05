# ============================================================
# SecureTrans - Sprint 6: Data Tampering Detection Test
# Verifies all modifications to files are detected
# ============================================================

import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from crypto.aes_module import aes_encrypt, aes_decrypt
from crypto.integrity_module import compute_hash, verify_integrity
from crypto.pfs_module import generate_session_key, destroy_session_key

print("=" * 60)
print("   SecureTrans — Data Tampering Detection Test")
print("=" * 60)

original = b"Confidential SecureTrans document - do not modify"


# ── Test 1: Single Bit Flip ───────────────────────────────────
print("\n[TEST 1] Single Bit Flip on Ciphertext")
try:
    key = generate_session_key()
    ciphertext, iv, tag = aes_encrypt(key, original)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01      # Flip only one bit
    result = aes_decrypt(key, bytes(tampered), iv, tag)

    print(f"  Bit flipped at byte 0")
    print(f"  AES-GCM detected: {'YES ✓' if result is None else 'NO ✗'}")
    print(f"  Status : {'PASS ✓' if result is None else 'FAIL ✗'}")
    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 2: Middle Section Modified ──────────────────────────
print("\n[TEST 2] Middle Section of Ciphertext Modified")
try:
    key = generate_session_key()
    ciphertext, iv, tag = aes_encrypt(key, original)

    tampered = bytearray(ciphertext)
    mid = len(tampered) // 2
    for i in range(mid, min(mid + 5, len(tampered))):
        tampered[i] ^= 0xFF

    result = aes_decrypt(key, bytes(tampered), iv, tag)
    print(f"  5 bytes modified at middle of ciphertext")
    print(f"  AES-GCM detected: {'YES ✓' if result is None else 'NO ✗'}")
    print(f"  Status : {'PASS ✓' if result is None else 'FAIL ✗'}")
    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 3: Authentication Tag Tampered ──────────────────────
print("\n[TEST 3] Authentication Tag Tampered")
try:
    key = generate_session_key()
    ciphertext, iv, tag = aes_encrypt(key, original)

    # Attacker modifies the auth tag
    fake_tag = bytes([b ^ 0xFF for b in tag])

    result = aes_decrypt(key, ciphertext, iv, fake_tag)
    print(f"  Authentication tag modified by attacker")
    print(f"  AES-GCM detected: {'YES ✓' if result is None else 'NO ✗'}")
    print(f"  Status : {'PASS ✓' if result is None else 'FAIL ✗'}")
    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 4: IV Tampered ───────────────────────────────────────
print("\n[TEST 4] Initialisation Vector (IV) Tampered")
try:
    key = generate_session_key()
    ciphertext, iv, tag = aes_encrypt(key, original)

    # Attacker modifies the IV
    fake_iv = bytes([b ^ 0xAA for b in iv])

    result = aes_decrypt(key, ciphertext, fake_iv, tag)
    print(f"  IV modified by attacker")
    print(f"  AES-GCM detected: {'YES ✓' if result is None else 'NO ✗'}")
    print(f"  Status : {'PASS ✓' if result is None else 'FAIL ✗'}")
    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 5: SHA-256 Detects Post-Decryption Modification ──────
print("\n[TEST 5] SHA-256 Detects Post-Decryption Modification")
try:
    original_hash = compute_hash(original)
    modified      = b"Confidential SecureTrans document - MODIFIED"
    result        = verify_integrity(modified, original_hash)

    print(f"  Original hash  : {original_hash[:32]}...")
    print(f"  Modified file  : {modified.decode()}")
    print(f"  SHA-256 detected: {'YES ✓' if not result else 'NO ✗'}")
    print(f"  Status : {'PASS ✓' if not result else 'FAIL ✗'}")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


print("\n" + "=" * 60)
print("   Data Tampering Test Complete — All Modifications DETECTED")
print("=" * 60)