# ============================================================
# SecureTrans - Comparison: Unencrypted Receiver
# Step 10 - For Wireshark comparison only
# This shows what an attacker sees WITHOUT encryption
# ============================================================

import socket

HOST = '0.0.0.0'
PORT = 65433        # Different port from SecureTrans

print("=" * 55)
print("   Unencrypted Receiver — Started")
print("   Listening on port 65433...")
print("=" * 55)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)

    print("\n[UNENCRYPTED] Waiting for connection...")
    conn, addr = s.accept()

    with conn:
        print(f"[UNENCRYPTED] Connected: {addr}")

        # Receive filename length first
        name_len = int.from_bytes(conn.recv(4), 'big')
        filename = conn.recv(name_len).decode()

        # Receive file size
        file_size = int.from_bytes(conn.recv(8), 'big')

        # Receive raw file content
        data = b''
        while len(data) < file_size:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        # Save received file
        import os
        os.makedirs('received_unencrypted', exist_ok=True)
        save_path = f'received_unencrypted/{filename}'

        with open(save_path, 'wb') as f:
            f.write(data)

        print(f"[UNENCRYPTED] File received: {filename}")
        print(f"[UNENCRYPTED] Size: {len(data)} bytes")
        print(f"[UNENCRYPTED] Saved to: {save_path}")
        print(f"\n[UNENCRYPTED] File content preview:")
        print(f"  {data[:100]}")

print("\n" + "=" * 55)
print("   Unencrypted Transfer Complete")
print("   CHECK WIRESHARK — plaintext should be visible!")
print("=" * 55)