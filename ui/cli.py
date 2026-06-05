
# ============================================================
# SecureTrans - Command Line Interface (CLI)
# Sprint 5 - CLI for Technical Users
# ============================================================

from pydoc import cli
import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from network.sender import send_file
from network.receiver import start_receiver


def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║           SecureTrans — Secure P2P               ║
║        File Exchange System v1.0                 ║
║                                                  ║
║  AES-256-GCM + RSA-2048 + Perfect Forward Secrecy║
║  SHA-256 Integrity + RSA-PSS Digital Signatures  ║
╚══════════════════════════════════════════════════╝
    """)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="SecureTrans — Secure P2P File Transfer",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        'mode',
        choices=['send', 'receive'],
        help=(
            "Mode to run:\n"
            "  send    — Send a file to a receiver\n"
            "  receive — Wait for an incoming file"
        )
    )

    parser.add_argument(
        '--file', '-f',
        type=str,
        help="Path to the file you want to send (required for send mode)"
    )

    parser.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help="Receiver's IP address (default: 127.0.0.1)"
    )

    parser.add_argument(
        '--port',
        type=int,
        default=65432,
        help="Port number (default: 65432)"
    )

    args = parser.parse_args()

    # ── SEND MODE ─────────────────────────────────────────────
    if args.mode == 'send':
        if not args.file:
            print("[ERROR] You must provide a file path with --file")
            print("Example: python ui/cli.py send --file report.pdf "
                  "--host 192.168.1.10")
            sys.exit(1)

        if not os.path.exists(args.file):
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)

        print(f"[CLI] Mode     : SEND")
        print(f"[CLI] File     : {args.file}")
        print(f"[CLI] Receiver : {args.host}:{args.port}")
        print()

        # Update host and port in sender dynamically
        import network.sender as sender_module
        sender_module.HOST = args.host
        sender_module.PORT = args.port

        send_file(args.file)

    # ── RECEIVE MODE ──────────────────────────────────────────
    elif args.mode == 'receive':
        print(f"[CLI] Mode : RECEIVE")
        print(f"[CLI] Port : {args.port}")
        print()

        import network.receiver as receiver_module
        receiver_module.PORT = args.port

        start_receiver()


if __name__ == '__main__':
    main()




   