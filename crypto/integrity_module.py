# ============================================================
# SecureTrans - Integrity Module
# Sprint 3 - SHA-256 File Integrity Verification
# ============================================================

from Crypto.Hash import SHA256


def compute_hash(file_bytes):
    """
    Computes the SHA-256 hash of a file's content.
    Called by SENDER before encryption.
    The hash is sent alongside the encrypted file.

    Args:
        file_bytes: raw file content in bytes

    Returns:
        hex string of SHA-256 digest (64 characters)
    """
    h = SHA256.new(file_bytes)
    digest = h.hexdigest()
    print(f"[SHA-256] Hash computed: {digest[:32]}...")
    return digest


def verify_integrity(file_bytes, expected_hash):
    """
    Verifies the integrity of a received file by comparing
    its SHA-256 hash against the hash sent by the sender.
    If they do not match, the file was modified in transit.

    Args:
        file_bytes   : the decrypted file content
        expected_hash: the hash string sent by the sender

    Returns:
        True if file is intact
        False if file has been modified
    """
    actual_hash = SHA256.new(file_bytes).hexdigest()

    if actual_hash == expected_hash:
        print("[SHA-256] Integrity check PASSED — File is intact ✓")
        return True
    else:
        print("[SHA-256] Integrity check FAILED — File has been modified!")
        print(f"  Expected : {expected_hash[:32]}...")
        print(f"  Actual   : {actual_hash[:32]}...")
        return False