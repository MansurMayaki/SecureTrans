# ============================================================
# SecureTrans - Sprint 6: Passive Interception Test
# Verifies encrypted traffic cannot be read in plaintext
# ============================================================

import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from crypto.pfs_module import generate_session_key, destroy_session_key
from crypto.aes_module import aes_encrypt, aes_decrypt
from crypto.rsa_module import (
    generate_rsa_keypair, export_public_key,
    rsa_encrypt, rsa_decrypt
)

print("=" * 60)
print("   SecureTrans — Passive Interception Test")
print("=" * 60)

# ── Test 1: Payload Not Visible in Ciphertext ────────────────
print("\n[TEST 1] File Payload Not Visible in Ciphertext")
try:
    key = generate_session_key()
    plaintext = b"CONFIDENTIAL: Q3 Financial Report Nigeria 2026"

    ciphertext, iv, tag = aes_encrypt(key, plaintext)

    # Simulate attacker reading the raw bytes on the wire
    attacker_sees = ciphertext

    # Check plaintext is NOT readable in ciphertext
    if plaintext not in attacker_sees:
        print(f"  Plaintext  : {plaintext.decode()}")
        print(f"  On wire    : {attacker_sees.hex()[:48]}...")
        print("  Plaintext NOT visible in captured bytes ✓")
        print("  Status     : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Plaintext visible in ciphertext!")

    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 2: Session Key Not Transmitted in Cleartext ─────────
print("\n[TEST 2] Session Key Encrypted Before Transmission")
try:
    receiver_key = generate_rsa_keypair()
    receiver_pub = export_public_key(receiver_key)

    session_key = generate_session_key()

    # Encrypt session key before sending
    encrypted_key = rsa_encrypt(receiver_pub, session_key)

    # Attacker captures encrypted_key on the wire
    # They cannot recover session_key without private key
    if session_key not in encrypted_key:
        print(f"  Raw session key    : {session_key.hex()[:24]}...")
        print(f"  What attacker sees : {encrypted_key.hex()[:24]}...")
        print("  Session key NOT visible in transmitted bytes ✓")
        print("  Status             : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Session key visible in transmission!")

    destroy_session_key(session_key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 3: Different Ciphertext Each Transfer (PFS) ─────────
print("\n[TEST 3] Different Ciphertext Per Transfer (PFS Proof)")
try:
    plaintext = b"Same file content sent twice"

    key1 = generate_session_key()
    key2 = generate_session_key()

    cipher1, iv1, tag1 = aes_encrypt(key1, plaintext)
    cipher2, iv2, tag2 = aes_encrypt(key2, plaintext)

    if cipher1 != cipher2 and iv1 != iv2:
        print(f"  Transfer 1 ciphertext : {cipher1.hex()[:24]}...")
        print(f"  Transfer 2 ciphertext : {cipher2.hex()[:24]}...")
        print("  Same file produces different ciphertext each time ✓")
        print("  Attacker cannot correlate transfers ✓")
        print("  Status : PASS ✓")
    else:
        print("  Status : FAIL ✗ — Ciphertexts are identical!")

    destroy_session_key(key1)
    destroy_session_key(key2)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


print("\n" + "=" * 60)
print("   Passive Interception Test Complete")
print("=" * 60)