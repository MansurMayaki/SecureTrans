
 ## Step 2 — How to use the CLI
#   To receive a file:
#   python3 ui/cli.py receive
#   To send a file:
#   python3 ui/cli.py send --file test_document.txt --host 127.0.0.1
#   To send to another computer on your LAN:
#   python3 ui/cli.py send --file report.pdf --host 192.168.1.10
#   To see all options:
#   python3 ui/cli.py --help
#  The CLI will guide you through the process with clear prompts and status updates.
# Run the GUI Terminal 1 — Start receiver GUI:
# python3 ui/gui.py

# Run the GUI Terminal 2 — Start sender GUI:
# python3 ui/gui.py


 Run all Sprint 6 evaluation tests
Run them one by one:
    python3 evaluation/test_passive_interception.py
    python3 evaluation/test_mitm_simulation.py
    python3 evaluation/test_data_tampering.py
    python3 evaluation/test_performance.py