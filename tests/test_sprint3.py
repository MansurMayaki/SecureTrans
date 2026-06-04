# ============================================================
# SecureTrans - Sprint 3 Test
# Tests for AES Module, PFS Module, Integrity Module
# ============================================================

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.aes_module import aes_encrypt, aes_decrypt
from crypto.pfs_module import generate_session_key, destroy_session_key
from crypto.integrity_module import compute_hash, verify_integrity

print("=" * 55)
print("   SecureTrans — Sprint 3: AES + PFS + Integrity Tests")
print("=" * 55)

# ── Test 1: AES-256-GCM Encrypt / Decrypt ───────────────────
print("\n[TEST 1] AES-256-GCM Encryption / Decryption")
try:
    key = generate_session_key()
    original = b"This is a test file content for SecureTrans AES test."

    ciphertext, iv, tag = aes_encrypt(key, original)
    print(f"  Ciphertext : {ciphertext.hex()[:32]}...")

    decrypted = aes_decrypt(key, ciphertext, iv, tag)

    if decrypted == original:
        print("  Decrypted  : Matches original ✓")
        print("  Status     : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Content mismatch")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 2: AES-GCM Tampered Data Detection ─────────────────
print("\n[TEST 2] AES-GCM — Tampered Ciphertext Detection")
try:
    key = generate_session_key()
    original = b"Sensitive file content that must not be tampered with."

    ciphertext, iv, tag = aes_encrypt(key, original)

    # Simulate tampering — flip one byte in the ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    tampered = bytes(tampered)

    result = aes_decrypt(key, tampered, iv, tag)

    if result is None:
        print("  Tampered ciphertext correctly REJECTED ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Tampered data was accepted")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 3: PFS — Unique Key Per Transfer ───────────────────
print("\n[TEST 3] PFS — Unique Session Key Per Transfer")
try:
    key1 = generate_session_key()
    key2 = generate_session_key()

    if key1 != key2:
        print(f"  Key 1 : {key1.hex()[:32]}...")
        print(f"  Key 2 : {key2.hex()[:32]}...")
        print("  Keys are different — PFS uniqueness confirmed ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Keys are identical")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 4: PFS — Session Key Destruction ───────────────────
print("\n[TEST 4] PFS — Session Key Secure Destruction")
try:
    key = generate_session_key()
    print(f"  Key before destruction : {key.hex()[:32]}...")
    destroy_session_key(key)
    print("  Status : PASS ✓")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 5: SHA-256 Integrity — Clean File ──────────────────
print("\n[TEST 5] SHA-256 Integrity — Clean File")
try:
    file_content = b"Original file sent by SecureTrans sender."
    file_hash = compute_hash(file_content)
    result = verify_integrity(file_content, file_hash)
    print(f"  Status : {'PASS ✓' if result else 'FAIL ✗'}")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 6: SHA-256 Integrity — Modified File ───────────────
print("\n[TEST 6] SHA-256 Integrity — Modified File Detection")
try:
    original_content  = b"Original file content from sender."
    modified_content  = b"MODIFIED file content by attacker."

    original_hash = compute_hash(original_content)
    result = verify_integrity(modified_content, original_hash)

    if not result:
        print("  Modified file correctly REJECTED ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Modified file was accepted")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 7: Full Sprint 2 + 3 Combined Flow ─────────────────
print("\n[TEST 7] Full Combined Flow — RSA + AES + PFS + Integrity")
try:
    from crypto.rsa_module import (
        generate_rsa_keypair, export_public_key,
        rsa_encrypt, rsa_decrypt,
        sign_file, verify_signature
    )

    # --- SENDER SIDE ---
    # Generate sender RSA key pair (for signing)
    sender_key = generate_rsa_keypair()
    sender_pub = export_public_key(sender_key)

    # Generate receiver RSA key pair (for key exchange)
    receiver_key = generate_rsa_keypair()
    receiver_pub = export_public_key(receiver_key)

    # File to send
    file_content = b"Confidential: Q3 Financial Report - SecureTrans"

    # Step 1: Compute hash and sign
    file_hash = compute_hash(file_content)
    signature = sign_file(sender_key, file_content)

    # Step 2: Generate PFS session key
    session_key = generate_session_key()

    # Step 3: Encrypt file with AES-256-GCM
    ciphertext, iv, auth_tag = aes_encrypt(session_key, file_content)

    # Step 4: Encrypt session key with receiver's RSA public key
    encrypted_session_key = rsa_encrypt(receiver_pub, session_key)

    # Destroy session key immediately after encryption
    destroy_session_key(session_key)

    # --- RECEIVER SIDE ---
    # Step 5: Decrypt session key with receiver's private key
    recovered_key = rsa_decrypt(receiver_key, encrypted_session_key)

    # Step 6: Decrypt file
    decrypted_file = aes_decrypt(recovered_key, ciphertext, iv, auth_tag)

    # Step 7: Verify signature
    sig_valid = verify_signature(sender_pub, decrypted_file, signature)

    # Step 8: Verify integrity
    integrity_valid = verify_integrity(decrypted_file, file_hash)

    # Destroy recovered session key
    destroy_session_key(recovered_key)

    if (decrypted_file == file_content
            and sig_valid and integrity_valid):
        print("  File transferred and verified successfully ✓")
        print("  Signature  : VALID ✓")
        print("  Integrity  : VALID ✓")
        print("  Content    : MATCHES ORIGINAL ✓")
        print("  Status     : PASS ✓ — Full pipeline working")
    else:
        print("  Status : FAIL ✗ — Pipeline failure")

except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Summary ──────────────────────────────────────────────────
print("\n" + "=" * 55)
print("   Sprint 3 Tests Complete")
print("   All PASS = Ready for Sprint 4 (Networking Layer)")
print("=" * 55)