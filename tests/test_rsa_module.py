# ============================================================
# SecureTrans - Sprint 2 Test
# Tests for RSA Module: Key Gen, OAEP, PSS, SHA-256
# ============================================================

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.rsa_module import (
    generate_rsa_keypair,
    export_public_key,
    export_private_key,
    rsa_encrypt,
    rsa_decrypt,
    sign_file,
    verify_signature,
    hash_file
)

print("=" * 55)
print("   SecureTrans — Sprint 2: RSA Module Tests")
print("=" * 55)

# ── Test 1: Key Generation ───────────────────────────────────
print("\n[TEST 1] RSA-2048 Key Generation")
try:
    key = generate_rsa_keypair()
    pub_bytes = export_public_key(key)
    priv_bytes = export_private_key(key)
    print(f"  Public Key Size  : {len(pub_bytes)} bytes")
    print(f"  Private Key Size : {len(priv_bytes)} bytes")
    print("  Status           : PASS ✓")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 2: RSA-OAEP Encrypt / Decrypt ──────────────────────
print("\n[TEST 2] RSA-OAEP Encrypt / Decrypt")
try:
    key = generate_rsa_keypair()
    pub_bytes = export_public_key(key)

    # Simulate an AES session key (32 random bytes)
    fake_session_key = os.urandom(32)
    print(f"  Original Session Key : {fake_session_key.hex()[:32]}...")

    # Sender encrypts
    encrypted_key = rsa_encrypt(pub_bytes, fake_session_key)
    print(f"  Encrypted Key        : {encrypted_key.hex()[:32]}...")

    # Receiver decrypts
    decrypted_key = rsa_decrypt(key, encrypted_key)
    print(f"  Decrypted Key        : {decrypted_key.hex()[:32]}...")

    if decrypted_key == fake_session_key:
        print("  Match                : Original == Decrypted ✓")
        print("  Status               : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Keys do not match")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 3: RSA-PSS Sign / Verify ───────────────────────────
print("\n[TEST 3] RSA-PSS Digital Signature — Valid File")
try:
    key = generate_rsa_keypair()
    pub_bytes = export_public_key(key)

    file_content = b"This is the content of a test file for SecureTrans."

    # Sender signs
    signature = sign_file(key, file_content)
    print(f"  Signature : {signature.hex()[:32]}...")

    # Receiver verifies
    result = verify_signature(pub_bytes, file_content, signature)
    print(f"  Status    : {'PASS ✓' if result else 'FAIL ✗'}")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 4: RSA-PSS — Tampered File Detection ────────────────
print("\n[TEST 4] RSA-PSS — Tampered File Detection")
try:
    key = generate_rsa_keypair()
    pub_bytes = export_public_key(key)

    original_file = b"Original file content."
    tampered_file = b"TAMPERED file content."

    # Sign original
    signature = sign_file(key, original_file)

    # Try to verify tampered file with original signature
    result = verify_signature(pub_bytes, tampered_file, signature)

    if not result:
        print("  Tampered file correctly REJECTED ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Tampered file was accepted")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Test 5: SHA-256 Hash Consistency ────────────────────────
print("\n[TEST 5] SHA-256 Hash Consistency")
try:
    data = b"SecureTrans file content for hashing."
    hash1 = hash_file(data)
    hash2 = hash_file(data)

    if hash1 == hash2:
        print(f"  Hash 1 : {hash1}")
        print(f"  Hash 2 : {hash2}")
        print("  Both hashes match for same input ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Hashes do not match")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")

# ── Summary ──────────────────────────────────────────────────
print("\n" + "=" * 55)
print("   Sprint 2 Tests Complete")
print("   All PASS = Ready for Sprint 3")
print("=" * 55)