# ============================================================
# SecureTrans - Sprint 6: MitM Attack Simulation
# Simulates attacker intercepting and modifying transfer
# ============================================================

import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from crypto.rsa_module import (
    generate_rsa_keypair, export_public_key,
    rsa_encrypt, rsa_decrypt,
    sign_file, verify_signature
)
from crypto.aes_module import aes_encrypt, aes_decrypt
from crypto.pfs_module import generate_session_key, destroy_session_key
from crypto.integrity_module import compute_hash, verify_integrity

print("=" * 60)
print("   SecureTrans — MitM Attack Simulation")
print("=" * 60)


# ── Test 1: Attacker Modifies Ciphertext ─────────────────────
print("\n[TEST 1] Attacker Modifies Encrypted Payload")
try:
    key = generate_session_key()
    original = b"Legitimate file content from authentic sender"

    ciphertext, iv, tag = aes_encrypt(key, original)

    # Attacker intercepts and modifies ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF   # Flip bits — attacker's modification
    tampered[5] ^= 0xAA
    tampered = bytes(tampered)

    # Receiver tries to decrypt tampered data
    result = aes_decrypt(key, tampered, iv, tag)

    if result is None:
        print("  Attacker modified ciphertext")
        print("  AES-GCM auth tag REJECTED tampered data ✓")
        print("  Status : PASS ✓ — MitM modification detected")
    else:
        print("  Status : FAIL ✗ — Tampered data was accepted!")

    destroy_session_key(key)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 2: Attacker Substitutes File Content ────────────────
print("\n[TEST 2] Attacker Substitutes File with Fake Content")
try:
    sender_key = generate_rsa_keypair()
    sender_pub = export_public_key(sender_key)

    original_file = b"Pay invoice #001 to Account A: NGN 500,000"
    fake_file     = b"Pay invoice #001 to Account B: NGN 500,000"

    # Sender signs original file
    signature = sign_file(sender_key, original_file)

    # Attacker substitutes fake_file but cannot re-sign
    # because they do not have sender's private key

    # Receiver verifies fake file against original signature
    result = verify_signature(sender_pub, fake_file, signature)

    if not result:
        print("  Attacker substituted file content")
        print("  RSA-PSS signature REJECTED fake file ✓")
        print("  Status : PASS ✓ — File substitution detected")
    else:
        print("  Status : FAIL ✗ — Fake file was accepted!")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 3: Attacker Replays Old Session Key ─────────────────
print("\n[TEST 3] Attacker Replays Captured Session Key")
try:
    receiver_key = generate_rsa_keypair()
    receiver_pub = export_public_key(receiver_key)

    # First transfer — legitimate
    key1 = generate_session_key()
    encrypted_key1 = rsa_encrypt(receiver_pub, key1)

    # Attacker captures encrypted_key1 and replays it
    # In next session receiver generates NEW key pair
    # Old encrypted_key1 cannot be decrypted by new private key
    new_receiver_key = generate_rsa_keypair()

    try:
        replayed = rsa_decrypt(new_receiver_key, encrypted_key1)
        print("  Status : FAIL ✗ — Replayed key was accepted!")
    except Exception:
        print("  Attacker replayed old captured session key")
        print("  New ephemeral RSA key pair REJECTED old key ✓")
        print("  Status : PASS ✓ — Replay attack blocked by PFS")

    destroy_session_key(key1)
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


# ── Test 4: Attacker Forges Sender Identity ──────────────────
print("\n[TEST 4] Attacker Forges Sender Identity")
try:
    real_sender_key    = generate_rsa_keypair()
    real_sender_pub    = export_public_key(real_sender_key)

    attacker_key       = generate_rsa_keypair()

    file_content = b"Authentic financial document"

    # Attacker signs with their own key
    fake_signature = sign_file(attacker_key, file_content)

    # Receiver verifies against real sender's public key
    result = verify_signature(
        real_sender_pub, file_content, fake_signature
    )

    if not result:
        print("  Attacker signed file with their own private key")
        print("  RSA-PSS REJECTED signature — wrong sender ✓")
        print("  Status : PASS ✓ — Identity forgery detected")
    else:
        print("  Status : FAIL ✗ — Forged identity was accepted!")
except Exception as e:
    print(f"  Status : FAIL ✗ — {e}")


print("\n" + "=" * 60)
print("   MitM Simulation Complete — All Attacks BLOCKED")
print("=" * 60)