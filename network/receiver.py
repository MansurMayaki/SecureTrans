# ============================================================
# SecureTrans - Receiver Module
# Sprint 4 - TCP/IP Socket-Based Secure File Receiver
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
    rsa_decrypt,
    verify_signature
)
from crypto.aes_module import aes_decrypt
from crypto.pfs_module import destroy_session_key
from crypto.integrity_module import verify_integrity

# ── CONSTANTS ─────────────────────────────────────────────────
HOST = '0.0.0.0'    # Listen on all interfaces
PORT = 65432
BUFFER = 4096
SAVE_FOLDER = 'received_files'


# ── HELPER: Receive length-prefixed data ─────────────────────

def receive_data(sock):
    """
    Receives length-prefixed data from socket.
    Reads the 4-byte header first to know how many
    bytes to expect, then reads exactly that many.
    """
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    total_length = struct.unpack('>I', raw_length)[0]

    data = b''
    while len(data) < total_length:
        chunk = sock.recv(min(BUFFER, total_length - len(data)))
        if not chunk:
            break
        data += chunk
    return data


# ── MAIN RECEIVER FUNCTION ────────────────────────────────────

def start_receiver():
    """
    Full SecureTrans secure file transfer — Receiver side.

    Steps:
    1.  Generate ephemeral RSA key pair (PFS)
    2.  Listen for incoming connection
    3.  Send RSA public key to sender
    4.  Receive encrypted session key
    5.  Decrypt session key with private key
    6.  Receive sender's public key
    7.  Receive file metadata
    8.  Receive digital signature
    9.  Receive encrypted file
    10. Decrypt file with AES-256-GCM
    11. Verify digital signature
    12. Verify SHA-256 integrity
    13. Save file if all checks pass
    14. Destroy session key
    15. Send confirmation to sender
    """

    # Create folder to save received files
    os.makedirs(SAVE_FOLDER, exist_ok=True)

    print("\n" + "=" * 55)
    print("   SecureTrans — Secure File Receiver")
    print("=" * 55)

    # Step 1: Generate ephemeral RSA key pair
    print("\n[RECEIVER] Step 1: Generating ephemeral RSA-2048 key pair...")
    receiver_key = generate_rsa_keypair()
    receiver_pub_bytes = export_public_key(receiver_key)
    print("[RECEIVER] Ephemeral key pair ready ✓")

    # Step 2: Start listening
    print(f"\n[RECEIVER] Step 2: Listening on port {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print("[RECEIVER] Waiting for sender connection...")

        conn, addr = server.accept()
        with conn:
            print(f"[RECEIVER] Connected: {addr} ✓")

            # Step 3: Send receiver's public key to sender
            print("\n[RECEIVER] Step 3: Sending public key to sender...")
            length = struct.pack('>I', len(receiver_pub_bytes))
            conn.sendall(length + receiver_pub_bytes)
            print("[RECEIVER] Public key sent ✓")

            # Step 4: Receive encrypted session key
            print("\n[RECEIVER] Step 4: Receiving encrypted session key...")
            encrypted_session_key = receive_data(conn)
            print("[RECEIVER] Encrypted session key received ✓")

            # Step 5: Decrypt session key
            print("\n[RECEIVER] Step 5: Decrypting session key with RSA-OAEP...")
            session_key = rsa_decrypt(receiver_key, encrypted_session_key)
            print("[RECEIVER] Session key recovered ✓")

            # Step 6: Receive sender's public key
            print("\n[RECEIVER] Step 6: Receiving sender's public key...")
            sender_pub_bytes = receive_data(conn)
            print("[RECEIVER] Sender's public key received ✓")

            # Step 7: Receive metadata
            print("\n[RECEIVER] Step 7: Receiving file metadata...")
            metadata_bytes = receive_data(conn)
            metadata = json.loads(metadata_bytes.decode())
            filename  = metadata['filename']
            file_hash = metadata['file_hash']
            iv        = bytes.fromhex(metadata['iv'])
            auth_tag  = bytes.fromhex(metadata['auth_tag'])
            print(f"[RECEIVER] Filename  : {filename}")
            print(f"[RECEIVER] Hash      : {file_hash[:32]}...")

            # Step 8: Receive digital signature
            print("\n[RECEIVER] Step 8: Receiving digital signature...")
            signature = receive_data(conn)
            print("[RECEIVER] Signature received ✓")

            # Step 9: Receive encrypted file
            print("\n[RECEIVER] Step 9: Receiving encrypted file...")
            ciphertext = receive_data(conn)
            print(f"[RECEIVER] Encrypted file received "
                  f"({len(ciphertext)} bytes) ✓")

            # Step 10: Decrypt file
            print("\n[RECEIVER] Step 10: Decrypting file with AES-256-GCM...")
            decrypted_file = aes_decrypt(
                session_key, ciphertext, iv, auth_tag
            )

            if decrypted_file is None:
                print("[RECEIVER] TRANSFER REJECTED — "
                      "AES authentication tag failed!")
                conn.sendall(
                    struct.pack('>I', len(b'REJECTED: Tampered data'))
                    + b'REJECTED: Tampered data'
                )
                return

            # Step 11: Verify digital signature
            print("\n[RECEIVER] Step 11: Verifying digital signature...")
            sig_valid = verify_signature(
                sender_pub_bytes, decrypted_file, signature
            )

            if not sig_valid:
                print("[RECEIVER] TRANSFER REJECTED — "
                      "Signature verification failed!")
                conn.sendall(
                    struct.pack('>I', len(b'REJECTED: Invalid signature'))
                    + b'REJECTED: Invalid signature'
                )
                return

            # Step 12: Verify SHA-256 integrity
            print("\n[RECEIVER] Step 12: Verifying SHA-256 integrity...")
            integrity_ok = verify_integrity(decrypted_file, file_hash)

            if not integrity_ok:
                print("[RECEIVER] TRANSFER REJECTED — "
                      "Integrity check failed!")
                conn.sendall(
                    struct.pack('>I', len(b'REJECTED: Integrity failure'))
                    + b'REJECTED: Integrity failure'
                )
                return

            # Step 13: Save file
            print(f"\n[RECEIVER] Step 13: Saving file...")
            save_path = os.path.join(SAVE_FOLDER, filename)
            with open(save_path, 'wb') as f:
                f.write(decrypted_file)
            print(f"[RECEIVER] File saved to: {save_path} ✓")

            # Step 14: Destroy session key
            print("\n[RECEIVER] Step 14: Destroying session key (PFS)...")
            destroy_session_key(session_key)

            # Step 15: Send confirmation
            print("\n[RECEIVER] Step 15: Sending confirmation to sender...")
            confirmation = (
                f"ACCEPTED: {filename} received, "
                f"verified, and saved successfully."
            )
            conn.sendall(
                struct.pack('>I', len(confirmation.encode()))
                + confirmation.encode()
            )

    print("\n" + "=" * 55)
    print("   Transfer Complete — All Security Checks PASSED")
    print("=" * 55)


# ── RUN ───────────────────────────────────────────────────────
if __name__ == '__main__':
    start_receiver()