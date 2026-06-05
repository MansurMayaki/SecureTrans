
# ============================================================
# SecureTrans - Graphical User Interface (GUI)
# Sprint 5 - Tkinter GUI for Non-Technical Users
# ============================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
import os
import io

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from network.sender import send_file
from network.receiver import start_receiver
import network.sender as sender_module
import network.receiver as receiver_module


# ── LOG REDIRECTOR ────────────────────────────────────────────
class LogRedirector(io.StringIO):
    """
    Redirects print() output from the crypto and network
    modules into the GUI log window in real time.
    """
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def write(self, message):
        if message.strip():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, message + '\n')
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')

    def flush(self):
        pass


# ── MAIN GUI CLASS ────────────────────────────────────────────
class SecureTransGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("SecureTrans — Secure P2P File Exchange")
        self.root.geometry("780x620")
        self.root.resizable(False, False)
        self.root.configure(bg="#0D1B2A")

        self.selected_file = tk.StringVar(value="No file selected")
        self.host_var      = tk.StringVar(value="127.0.0.1")
        self.port_var      = tk.StringVar(value="65432")
        self.mode_var      = tk.StringVar(value="send")

        self._build_ui()

    def _build_ui(self):

        # ── HEADER ────────────────────────────────────────────
        header = tk.Frame(self.root, bg="#028090", height=70)
        header.pack(fill='x')
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🔒  SecureTrans",
            font=("Calibri", 22, "bold"),
            bg="#028090", fg="white"
        ).pack(side='left', padx=20, pady=15)

        tk.Label(
            header,
            text="AES-256-GCM  |  RSA-2048  |  Perfect Forward Secrecy",
            font=("Calibri", 10),
            bg="#028090", fg="#D0EEE8"
        ).pack(side='right', padx=20, pady=15)

        # ── MODE SELECTION ────────────────────────────────────
        mode_frame = tk.Frame(self.root, bg="#1B2B4B", pady=12)
        mode_frame.pack(fill='x')

        tk.Label(
            mode_frame,
            text="Select Mode:",
            font=("Calibri", 12, "bold"),
            bg="#1B2B4B", fg="white"
        ).pack(side='left', padx=20)

        tk.Radiobutton(
            mode_frame, text="  Send File",
            variable=self.mode_var, value="send",
            font=("Calibri", 12), bg="#1B2B4B",
            fg="#02C39A", selectcolor="#1B2B4B",
            activebackground="#1B2B4B",
            command=self._toggle_mode
        ).pack(side='left', padx=10)

        tk.Radiobutton(
            mode_frame, text="  Receive File",
            variable=self.mode_var, value="receive",
            font=("Calibri", 12), bg="#1B2B4B",
            fg="#02C39A", selectcolor="#1B2B4B",
            activebackground="#1B2B4B",
            command=self._toggle_mode
        ).pack(side='left', padx=10)

        # ── SEND PANEL ────────────────────────────────────────
        self.send_panel = tk.Frame(
            self.root, bg="#0D1B2A", pady=10
        )
        self.send_panel.pack(fill='x', padx=20)

        # File selection
        file_row = tk.Frame(self.send_panel, bg="#0D1B2A")
        file_row.pack(fill='x', pady=5)

        tk.Label(
            file_row, text="File:",
            font=("Calibri", 11, "bold"),
            bg="#0D1B2A", fg="white", width=8, anchor='w'
        ).pack(side='left')

        tk.Entry(
            file_row,
            textvariable=self.selected_file,
            font=("Calibri", 10), width=52,
            bg="#112233", fg="#C8D8E4",
            insertbackground="white",
            relief='flat', bd=4
        ).pack(side='left', padx=5)

        tk.Button(
            file_row, text="Browse",
            font=("Calibri", 10, "bold"),
            bg="#028090", fg="white",
            relief='flat', padx=10,
            cursor="hand2",
            command=self._browse_file
        ).pack(side='left', padx=5)

        # Host input
        host_row = tk.Frame(self.send_panel, bg="#0D1B2A")
        host_row.pack(fill='x', pady=5)

        tk.Label(
            host_row, text="Host IP:",
            font=("Calibri", 11, "bold"),
            bg="#0D1B2A", fg="white", width=8, anchor='w'
        ).pack(side='left')

        tk.Entry(
            host_row,
            textvariable=self.host_var,
            font=("Calibri", 10), width=20,
            bg="#112233", fg="#C8D8E4",
            insertbackground="white",
            relief='flat', bd=4
        ).pack(side='left', padx=5)

        tk.Label(
            host_row, text="Port:",
            font=("Calibri", 11, "bold"),
            bg="#0D1B2A", fg="white", padx=15
        ).pack(side='left')

        tk.Entry(
            host_row,
            textvariable=self.port_var,
            font=("Calibri", 10), width=8,
            bg="#112233", fg="#C8D8E4",
            insertbackground="white",
            relief='flat', bd=4
        ).pack(side='left', padx=5)

        # ── RECEIVE PANEL ─────────────────────────────────────
        self.receive_panel = tk.Frame(
            self.root, bg="#0D1B2A", pady=10
        )

        tk.Label(
            self.receive_panel,
            text="Listening for incoming secure file transfers...",
            font=("Calibri", 11, "italic"),
            bg="#0D1B2A", fg="#8FA3B1"
        ).pack(padx=20, pady=5, anchor='w')

        tk.Label(
            self.receive_panel,
            text="Files will be saved to:  received_files/",
            font=("Calibri", 11),
            bg="#0D1B2A", fg="#02C39A"
        ).pack(padx=20, anchor='w')

        # ── ACTION BUTTON ─────────────────────────────────────
        btn_frame = tk.Frame(self.root, bg="#0D1B2A", pady=8)
        btn_frame.pack(fill='x', padx=20)

        self.action_btn = tk.Button(
            btn_frame,
            text="🔒  Send File Securely",
            font=("Calibri", 13, "bold"),
            bg="#02C39A", fg="#0D1B2A",
            relief='flat', padx=20, pady=10,
            cursor="hand2",
            command=self._run_action
        )
        self.action_btn.pack(fill='x')

        # ── STATUS BAR ────────────────────────────────────────
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Calibri", 10, "bold"),
            bg="#028090", fg="white",
            anchor='w', padx=15, pady=4
        )
        status_bar.pack(fill='x', padx=0)

        # ── PROGRESS BAR ──────────────────────────────────────
        self.progress = ttk.Progressbar(
            self.root, mode='indeterminate', length=780
        )
        self.progress.pack(fill='x')

        # ── LOG WINDOW ────────────────────────────────────────
        log_label = tk.Label(
            self.root,
            text="Transfer Log:",
            font=("Calibri", 10, "bold"),
            bg="#0D1B2A", fg="#8FA3B1",
            anchor='w'
        )
        log_label.pack(fill='x', padx=20, pady=(8, 0))

        self.log = scrolledtext.ScrolledText(
            self.root,
            font=("Courier New", 9),
            bg="#050F1A", fg="#02C39A",
            insertbackground="white",
            relief='flat', bd=0,
            state='disabled', height=14
        )
        self.log.pack(fill='both', expand=True, padx=20, pady=(0, 15))

        # Redirect stdout to log window
        sys.stdout = LogRedirector(self.log)

    # ── HELPER METHODS ────────────────────────────────────────

    def _toggle_mode(self):
        if self.mode_var.get() == 'send':
            self.receive_panel.pack_forget()
            self.send_panel.pack(fill='x', padx=20)
            self.action_btn.config(text="🔒  Send File Securely")
        else:
            self.send_panel.pack_forget()
            self.receive_panel.pack(fill='x', padx=20)
            self.action_btn.config(text="📥  Start Receiving")

    def _browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files",        "*.*"),
                ("PDF files",        "*.pdf"),
                ("Word documents",   "*.docx"),
                ("Text files",       "*.txt"),
                ("Image files",      "*.jpg *.jpeg *.png"),
            ]
        )
        if filepath:
            self.selected_file.set(filepath)

    def _log(self, message, color="#02C39A"):
        self.log.configure(state='normal')
        self.log.insert(tk.END, message + '\n')
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def _set_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def _run_action(self):
        self.action_btn.config(state='disabled')
        self.progress.start(10)

        if self.mode_var.get() == 'send':
            threading.Thread(
                target=self._send_thread, daemon=True
            ).start()
        else:
            threading.Thread(
                target=self._receive_thread, daemon=True
            ).start()

    def _send_thread(self):
        filepath = self.selected_file.get()
        host     = self.host_var.get()
        port     = int(self.port_var.get())

        if filepath == "No file selected" or not os.path.exists(filepath):
            messagebox.showerror(
                "File Error",
                "Please select a valid file to send."
            )
            self._reset_ui()
            return

        self._set_status(f"Connecting to {host}:{port}...")
        self._log(f"\n[GUI] Starting secure transfer to {host}:{port}")

        try:
            sender_module.HOST = host
            sender_module.PORT = port
            send_file(filepath)
            self._set_status("✓ Transfer Complete — All security checks passed")
            messagebox.showinfo(
                "Transfer Complete",
                f"File sent and verified successfully!\n\n"
                f"File     : {os.path.basename(filepath)}\n"
                f"Receiver : {host}:{port}\n\n"
                f"✓ AES-256-GCM encryption\n"
                f"✓ RSA-2048 key exchange\n"
                f"✓ Perfect Forward Secrecy\n"
                f"✓ Digital signature verified\n"
                f"✓ SHA-256 integrity verified"
            )
        except ConnectionRefusedError:
            self._set_status("✗ Connection failed — Is receiver running?")
            messagebox.showerror(
                "Connection Error",
                f"Could not connect to {host}:{port}\n\n"
                f"Make sure the receiver is running first."
            )
        except Exception as e:
            self._set_status(f"✗ Transfer failed: {str(e)}")
            messagebox.showerror("Transfer Error", str(e))
        finally:
            self._reset_ui()

    def _receive_thread(self):
        port = int(self.port_var.get())
        self._set_status(f"Listening on port {port}...")
        self._log(f"\n[GUI] Starting receiver on port {port}")

        try:
            receiver_module.PORT = port
            start_receiver()
            self._set_status("✓ File received and verified successfully")
            messagebox.showinfo(
                "File Received",
                "File received and all security checks passed!\n\n"
                f"✓ AES-256-GCM decryption\n"
                f"✓ RSA-PSS signature verified\n"
                f"✓ SHA-256 integrity verified\n\n"
                f"File saved to: received_files/"
            )
        except Exception as e:
            self._set_status(f"✗ Receiver error: {str(e)}")
            messagebox.showerror("Receiver Error", str(e))
        finally:
            self._reset_ui()

    def _reset_ui(self):
        self.progress.stop()
        self.action_btn.config(state='normal')
        self.root.update_idletasks()


# ── RUN ───────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    app = SecureTransGUI(root)
    root.mainloop()
    sys.stdout = sys.__stdout__


if __name__ == '__main__':
    main()