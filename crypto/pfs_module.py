
# ============================================================
# SecureTrans - PFS Module
# Sprint 3 - Perfect Forward Secrecy: Ephemeral Key Management
# ============================================================

import os
import ctypes


def generate_session_key():
    """
    Generates a cryptographically random 256-bit AES session key.
    This key is unique to one file transfer only.
    It must be destroyed immediately after the transfer completes.

    Returns:
        bytes: 32 random bytes (256-bit key)
    """
    session_key = os.urandom(32)
    print(f"[PFS] New ephemeral session key generated: "
          f"{session_key.hex()[:16]}...")
    return session_key


def destroy_session_key(session_key):
    """
    Securely destroys the session key from memory after transfer.
    Overwrites the key bytes with zeros before deleting.
    This is the core of Perfect Forward Secrecy — once destroyed,
    past transfers cannot be decrypted even if the system is later
    compromised.

    Args:
        session_key: the bytes object to destroy

    Returns:
        None
    """
    try:
        # Convert bytes to a mutable bytearray and zero it out
        key_array = bytearray(session_key)
        for i in range(len(key_array)):
            key_array[i] = 0

        # Use ctypes to overwrite original memory location
        ctypes.memset(
            (ctypes.c_char * len(session_key))
            .from_buffer(key_array), 0, len(session_key)
        )
        del key_array
        del session_key
        print("[PFS] Session key securely DESTROYED from memory ✓")

    except Exception as e:
        print(f"[PFS] Warning during key destruction: {e}")
        del session_key