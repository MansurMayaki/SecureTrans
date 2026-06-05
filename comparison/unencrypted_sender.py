# ============================================================
# SecureTrans - Comparison: Unencrypted Sender
# Step 10 - For Wireshark comparison only
# This shows what an attacker sees WITHOUT encryption
# ============================================================

import socket
import os
import sys

HOST = '127.0.0.1'
PORT = 65433        # Different port from SecureTrans

if len(sys.argv) < 2:
    print("Usage: python comparison/unencrypted_sender.py <filepath>")
    print("Example: python comparison/unencrypted_sender.py test_document.txt")
    sys.exit(1)

filepath = sys.argv[1]

if not os.path.exists(filepath):
    print(f"[ERROR] File not found: {filepath}")
    sys.exit(1)

print("=" * 55)
print("   Unencrypted Sender — Started")
print("=" * 55)

# Read the file
with open(filepath, 'rb') as f:
    file_bytes = f.read()

filename = os.path.basename(filepath)
filesize = len(file_bytes)

print(f"\n[UNENCRYPTED] File     : {filename}")
print(f"[UNENCRYPTED] Size     : {filesize} bytes")
print(f"[UNENCRYPTED] Sending  : RAW — NO ENCRYPTION")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[UNENCRYPTED] Connected to {HOST}:{PORT}")

    # Send filename
    name_bytes = filename.encode()
    s.sendall(len(name_bytes).to_bytes(4, 'big'))
    s.sendall(name_bytes)

    # Send file size
    s.sendall(filesize.to_bytes(8, 'big'))

    # Send raw file content — NO ENCRYPTION
    s.sendall(file_bytes)

    print(f"[UNENCRYPTED] File sent in PLAINTEXT")
    print(f"[UNENCRYPTED] Content preview: {file_bytes[:80]}")

print("\n" + "=" * 55)
print("   Unencrypted Transfer Complete")
print("   CHECK WIRESHARK — you should see plaintext!")
print("=" * 55)