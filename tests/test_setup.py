# ============================================================
# SecureTrans - Task 4: Technology Verification Script
# Sprint 1 - Environment Setup Test
# ============================================================

import sys
import socket

print("=" * 55)
print("   SecureTrans — Technology Verification")
print("=" * 55)

# ── Test 1: Python Version ───────────────────────────────────
print("\n[TEST 1] Python Version")
print(f"  Version : {sys.version}")
major, minor = sys.version_info[:2]
if major == 3 and minor >= 8:
    print("  Status  : PASS ✓ — Python 3.8+ confirmed")
else:
    print("  Status  : FAIL ✗ — Please install Python 3.8 or newer")

# ── Test 2: PyCryptodome — RSA-2048 ─────────────────────────
print("\n[TEST 2] PyCryptodome — RSA-2048 Key Generation")
try:
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    pub_key = key.publickey()
    print(f"  Key Size   : {key.size_in_bits()} bits")
    print(f"  Public Key : {str(pub_key.export_key())[:50]}...")
    print("  Status     : PASS ✓ — RSA-2048 working")
except ImportError:
    print("  Status : FAIL ✗ — PyCryptodome not installed")
    print("  Fix    : Run --> pip install pycryptodome")

# ── Test 3: PyCryptodome — RSA-OAEP Encryption ──────────────
print("\n[TEST 3] PyCryptodome — RSA-OAEP Encryption/Decryption")
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256

    key = RSA.generate(2048)
    test_message = b"SecureTrans test session key"

    # Encrypt with public key
    cipher_rsa = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)
    encrypted = cipher_rsa.encrypt(test_message)

    # Decrypt with private key
    decipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    decrypted = decipher_rsa.decrypt(encrypted)

    if decrypted == test_message:
        print("  Encrypted  : Successfully encrypted with public key")
        print("  Decrypted  : Successfully decrypted with private key")
        print("  Match      : Original == Decrypted ✓")
        print("  Status     : PASS ✓ — RSA-OAEP working")
    else:
        print("  Status : FAIL ✗ — Decrypted message does not match")
except Exception as e:
    print(f"  Status : FAIL ✗ — Error: {e}")

# ── Test 4: PyCryptodome — AES-256-GCM ──────────────────────
print("\n[TEST 4] PyCryptodome — AES-256-GCM Encryption/Decryption")
try:
    from Crypto.Cipher import AES
    import os

    # Generate random 256-bit key and 96-bit IV
    aes_key = os.urandom(32)   # 256 bits
    iv      = os.urandom(12)   # 96 bits — NIST recommended for GCM

    plaintext = b"SecureTrans test file content 1234"

    # Encrypt
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext)

    # Decrypt
    decipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    decrypted = decipher_aes.decrypt_and_verify(ciphertext, auth_tag)

    if decrypted == plaintext:
        print(f"  Key Size   : {len(aes_key) * 8} bits")
        print(f"  IV Size    : {len(iv) * 8} bits")
        print(f"  Auth Tag   : {auth_tag.hex()[:32]}...")
        print("  Status     : PASS ✓ — AES-256-GCM working")
    else:
        print("  Status : FAIL ✗ — Decrypted content does not match")
except Exception as e:
    print(f"  Status : FAIL ✗ — Error: {e}")

# ── Test 5: PyCryptodome — RSA-PSS Digital Signature ────────
print("\n[TEST 5] PyCryptodome — RSA-PSS Digital Signature")
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256

    key = RSA.generate(2048)
    message = b"SecureTrans test file for signing"

    # Sign with private key
    h = SHA256.new(message)
    signature = pss.new(key).sign(h)

    # Verify with public key
    h_verify = SHA256.new(message)
    try:
        pss.new(key.publickey()).verify(h_verify, signature)
        print("  Signed     : Successfully signed with private key")
        print("  Verified   : Successfully verified with public key")
        print("  Status     : PASS ✓ — RSA-PSS Digital Signature working")
    except Exception:
        print("  Status : FAIL ✗ — Signature verification failed")
except Exception as e:
    print(f"  Status : FAIL ✗ — Error: {e}")

# ── Test 6: PyCryptodome — SHA-256 Hashing ──────────────────
print("\n[TEST 6] PyCryptodome — SHA-256 Integrity Hashing")
try:
    from Crypto.Hash import SHA256

    data = b"SecureTrans test file content"
    hash_result = SHA256.new(data).hexdigest()

    print(f"  Input      : {data.decode()}")
    print(f"  SHA-256    : {hash_result}")
    print(f"  Length     : {len(hash_result) * 4} bits")
    print("  Status     : PASS ✓ — SHA-256 hashing working")
except Exception as e:
    print(f"  Status : FAIL ✗ — Error: {e}")

# ── Test 7: Python Socket Library ───────────────────────────
print("\n[TEST 7] Python Socket Library — TCP/IP")
try:
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"  Hostname   : {hostname}")
    print(f"  Local IP   : {local_ip}")
    print(f"  Library    : {socket.__name__} (built-in)")
    print("  Status     : PASS ✓ — Socket library working")
except Exception as e:
    print(f"  Status : FAIL ✗ — Error: {e}")

# ── Test 8: Tkinter GUI Library ─────────────────────────────
print("\n[TEST 8] Tkinter — GUI Library")
try:
    import tkinter
    version = tkinter.TkVersion
    print(f"  Tk Version : {version}")
    print("  Status     : PASS ✓ — Tkinter available")
except ImportError:
    print("  Status : FAIL ✗ — Tkinter not available")
    print("  Fix    : On Linux run --> sudo apt install python3-tk")

# ── Final Summary ────────────────────────────────────────────
print("\n" + "=" * 55)
print("   Verification Complete")
print("   If all 8 tests show PASS, your environment is")
print("   ready to begin Sprint 2 implementation.")
print("=" * 55)