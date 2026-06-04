# ============================================================
# SecureTrans - Sender Module
# Sprint 4 - TCP/IP Socket-Based Secure File Sender
# ============================================================

import socket
import os
import json
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.rsa_module import (
    generate_rsa_keypair,
    export_public_key,
    rsa_encrypt,
    sign_file
)
from crypto.aes_module import aes_encrypt
from crypto.pfs_module import generate_session_key, destroy_session_key
from crypto.integrity_module import compute_hash

# ── CONSTANTS ─────────────────────────────────────────────────
HOST = '127.0.0.1'   # Change to receiver's IP on real LAN
PORT = 65432
BUFFER = 4096


# ── HELPER: Send length-prefixed data ────────────────────────

def send_data(sock, data):
    """
    Sends data over socket with a 4-byte length prefix.
    This ensures the receiver knows exactly how many
    bytes to read for each piece of data.
    """
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)


# ── MAIN SENDER FUNCTION ──────────────────────────────────────

def send_file(filepath):
    """
    Full SecureTrans secure file transfer — Sender side.

    Steps:
    1.  Connect to receiver
    2.  Receive receiver's RSA public key
    3.  Generate PFS session key
    4.  Encrypt session key with receiver's RSA public key
    5.  Send encrypted session key
    6.  Send sender's RSA public key (for signature verification)
    7.  Read file content
    8.  Compute SHA-256 hash of file
    9.  Sign file with sender's private key
    10. Encrypt file with AES-256-GCM
    11. Send filename, hash, signature, IV, auth tag, ciphertext
    12. Destroy session key
    """

    if not os.path.exists(filepath):
        print(f"[SENDER] Error: File not found — {filepath}")
        return

    print("\n" + "=" * 55)
    print("   SecureTrans — Secure File Sender")
    print("=" * 55)
    print(f"[SENDER] Preparing to send: {filepath}")

    # Step 1: Generate sender RSA key pair
    print("\n[SENDER] Step 1: Generating sender RSA-2048 key pair...")
    sender_key = generate_rsa_keypair()
    sender_pub_bytes = export_public_key(sender_key)

    # Step 2: Connect to receiver
    print(f"\n[SENDER] Step 2: Connecting to receiver at {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[SENDER] Connected to receiver ✓")

        # Step 3: Receive receiver's RSA public key
        print("\n[SENDER] Step 3: Receiving receiver's RSA public key...")
        receiver_pub_length = struct.unpack('>I', s.recv(4))[0]
        receiver_pub_bytes = b''
        while len(receiver_pub_bytes) < receiver_pub_length:
            chunk = s.recv(min(BUFFER, receiver_pub_length
                               - len(receiver_pub_bytes)))
            receiver_pub_bytes += chunk
        print("[SENDER] Receiver's public key received ✓")

        # Step 4: Generate PFS session key
        print("\n[SENDER] Step 4: Generating ephemeral PFS session key...")
        session_key = generate_session_key()

        # Step 5: Encrypt session key with receiver's RSA public key
        print("\n[SENDER] Step 5: Encrypting session key with RSA-OAEP...")
        encrypted_session_key = rsa_encrypt(receiver_pub_bytes, session_key)

        # Step 6: Send encrypted session key
        print("\n[SENDER] Step 6: Sending encrypted session key...")
        send_data(s, encrypted_session_key)
        print("[SENDER] Encrypted session key sent ✓")

        # Step 7: Send sender's public key
        print("\n[SENDER] Step 7: Sending sender's public key...")
        send_data(s, sender_pub_bytes)
        print("[SENDER] Sender's public key sent ✓")

        # Step 8: Read file
        print(f"\n[SENDER] Step 8: Reading file: {filepath}...")
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
        filename = os.path.basename(filepath)
        filesize = len(file_bytes)
        print(f"[SENDER] File read: {filename} ({filesize} bytes)")

        # Step 9: Compute SHA-256 hash
        print("\n[SENDER] Step 9: Computing SHA-256 hash...")
        file_hash = compute_hash(file_bytes)

        # Step 10: Sign file with sender's private key
        print("\n[SENDER] Step 10: Signing file with RSA-PSS...")
        signature = sign_file(sender_key, file_bytes)

        # Step 11: Encrypt file with AES-256-GCM
        print("\n[SENDER] Step 11: Encrypting file with AES-256-GCM...")
        ciphertext, iv, auth_tag = aes_encrypt(session_key, file_bytes)

        # Step 12: Build and send metadata packet
        print("\n[SENDER] Step 12: Sending file metadata...")
        metadata = {
            'filename'  : filename,
            'filesize'  : filesize,
            'file_hash' : file_hash,
            'iv'        : iv.hex(),
            'auth_tag'  : auth_tag.hex()
        }
        metadata_bytes = json.dumps(metadata).encode()
        send_data(s, metadata_bytes)
        print(f"[SENDER] Metadata sent: {metadata['filename']}")

        # Step 13: Send digital signature
        print("\n[SENDER] Step 13: Sending digital signature...")
        send_data(s, signature)
        print("[SENDER] Signature sent ✓")

        # Step 14: Send encrypted file
        print("\n[SENDER] Step 14: Sending encrypted file...")
        send_data(s, ciphertext)
        print(f"[SENDER] Encrypted file sent ({len(ciphertext)} bytes) ✓")

        # Step 15: Destroy session key — PFS
        print("\n[SENDER] Step 15: Destroying session key (PFS)...")
        destroy_session_key(session_key)

        # Step 16: Wait for receiver confirmation
        print("\n[SENDER] Step 16: Waiting for receiver confirmation...")
        conf_length = struct.unpack('>I', s.recv(4))[0]
        confirmation = s.recv(conf_length).decode()
        print(f"[SENDER] Receiver says: {confirmation}")

    print("\n" + "=" * 55)
    print("   Transfer Complete")
    print("=" * 55)


# ── RUN ───────────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python network/sender.py <filepath>")
        print("Example: python network/sender.py docs/report.pdf")
    else:
        send_file(sys.argv[1])