# ============================================================
# SecureTrans - RSA Module
# Sprint 2 - RSA-2048 Key Generation, OAEP, PSS
# ============================================================

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


# ── 1. KEY GENERATION ────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generates a fresh RSA-2048 key pair.
    Returns the private key object.
    The public key is extracted from it.
    """
    print("[RSA] Generating RSA-2048 key pair...")
    key = RSA.generate(2048)
    print("[RSA] Key pair generated successfully.")
    return key


def export_public_key(key):
    """
    Exports the public key as bytes (PEM format).
    This is what gets sent over the network to the sender.
    """
    return key.publickey().export_key()


def export_private_key(key):
    """
    Exports the private key as bytes (PEM format).
    This NEVER leaves the receiver's machine.
    """
    return key.export_key()


def load_public_key(pub_key_bytes):
    """
    Loads a public key from bytes received over the network.
    """
    return RSA.import_key(pub_key_bytes)


def load_private_key(priv_key_bytes):
    """
    Loads a private key from bytes.
    """
    return RSA.import_key(priv_key_bytes)


# ── 2. RSA-OAEP ENCRYPTION / DECRYPTION ─────────────────────

def rsa_encrypt(public_key_bytes, plaintext_bytes):
    """
    Encrypts plaintext using RSA-OAEP with SHA-256.
    Used by the SENDER to encrypt the AES session key.

    Args:
        public_key_bytes : receiver's public key in PEM bytes
        plaintext_bytes  : the AES session key (32 bytes)

    Returns:
        ciphertext bytes
    """
    pub_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    ciphertext = cipher.encrypt(plaintext_bytes)
    print("[RSA-OAEP] Session key encrypted with receiver's public key.")
    return ciphertext


def rsa_decrypt(private_key, ciphertext_bytes):
    """
    Decrypts ciphertext using RSA-OAEP with SHA-256.
    Used by the RECEIVER to recover the AES session key.

    Args:
        private_key     : receiver's RSA private key object
        ciphertext_bytes: the encrypted AES session key

    Returns:
        plaintext bytes (the AES session key)
    """
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    plaintext = cipher.decrypt(ciphertext_bytes)
    print("[RSA-OAEP] Session key decrypted with receiver's private key.")
    return plaintext


# ── 3. RSA-PSS DIGITAL SIGNATURE / VERIFICATION ─────────────

def sign_file(private_key, file_bytes):
    """
    Signs a SHA-256 hash of the file using RSA-PSS.
    Used by the SENDER to prove identity and file integrity.

    Args:
        private_key : sender's RSA private key object
        file_bytes  : the raw plaintext file content

    Returns:
        signature bytes
    """
    h = SHA256.new(file_bytes)
    signature = pss.new(private_key).sign(h)
    print("[RSA-PSS] File signed with sender's private key.")
    return signature


def verify_signature(public_key_bytes, file_bytes, signature):
    """
    Verifies the RSA-PSS signature on a file.
    Used by the RECEIVER to confirm sender identity.

    Args:
        public_key_bytes : sender's public key in PEM bytes
        file_bytes       : the decrypted file content
        signature        : the signature bytes from sender

    Returns:
        True if valid, False if tampered or wrong sender
    """
    pub_key = RSA.import_key(public_key_bytes)
    h = SHA256.new(file_bytes)
    try:
        pss.new(pub_key).verify(h, signature)
        print("[RSA-PSS] Signature VERIFIED. Sender is authentic.")
        return True
    except (ValueError, TypeError):
        print("[RSA-PSS] Signature FAILED. File may be tampered or sender unknown.")
        return False


# ── 4. SHA-256 FILE HASH ─────────────────────────────────────

def hash_file(file_bytes):
    """
    Computes SHA-256 hash of file content.
    Used for integrity verification at the receiver side.

    Args:
        file_bytes : raw file content in bytes

    Returns:
        hex string of the SHA-256 digest
    """
    h = SHA256.new(file_bytes)
    digest = h.hexdigest()
    print(f"[SHA-256] File hash computed: {digest[:32]}...")
    return digest