
# ============================================================
# SecureTrans - AES Module
# Sprint 3 - AES-256-GCM Encryption Engine
# ============================================================

import os
from Crypto.Cipher import AES


# ── 1. AES-256-GCM ENCRYPTION ────────────────────────────────

def aes_encrypt(session_key, plaintext_bytes):
    """
    Encrypts plaintext using AES-256-GCM.
    Generates a unique random 96-bit IV for every call.
    Returns ciphertext, IV, and authentication tag.

    Args:
        session_key    : 32-byte AES key (from PFS module)
        plaintext_bytes: raw file content in bytes

    Returns:
        tuple: (ciphertext, iv, auth_tag)
    """
    iv = os.urandom(12)  # 96-bit IV — NIST SP 800-38D recommendation
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext_bytes)

    print(f"[AES-GCM] File encrypted. IV: {iv.hex()[:16]}... "
          f"Tag: {auth_tag.hex()[:16]}...")
    return ciphertext, iv, auth_tag


# ── 2. AES-256-GCM DECRYPTION ────────────────────────────────

def aes_decrypt(session_key, ciphertext_bytes, iv, auth_tag):
    """
    Decrypts ciphertext using AES-256-GCM.
    Automatically verifies the authentication tag.
    If the tag fails, the file was tampered — raises an error.

    Args:
        session_key     : 32-byte AES key
        ciphertext_bytes: encrypted file content
        iv              : the IV used during encryption
        auth_tag        : the GCM authentication tag

    Returns:
        plaintext bytes if successful
        None if authentication tag fails (tampered data)
    """
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext_bytes, auth_tag)
        print("[AES-GCM] File decrypted and authentication tag VERIFIED ✓")
        return plaintext
    except ValueError:
        print("[AES-GCM] AUTHENTICATION TAG FAILED — File may be tampered!")
        return None