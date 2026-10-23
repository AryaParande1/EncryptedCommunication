"""Tkinter chat client with separate server and user send buttons."""

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

from client.network import NetworkClient
from security.message_encryption import decrypt_with_shared_key, encrypt_with_shared_key


def caesar_cipher(text: str, shift: int = 3) -> str:
    """Shift letters for the server-message demo mode (not secure encryption)."""
    result = []
    for character in text:
        if "a" <= character <= "z":
            result.append(chr((ord(character) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= character <= "Z":
            result.append(chr((ord(character) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(character)
    return "".join(result)


def caesar_decipher(text: str, shift: int = 3) -> str:
    """Reverse the demo shift applied to a server message."""
    return caesar_cipher(text, -shift)


class CommunicationApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Communication Client")
        self.root.geometry("760x620")
        self.root.minsize(560, 460)
        self.client = NetworkClient(
            on_message=self._on_message,
            on_disconnect=self._on_disconnect,
        )
        self.username = ""
        self._build_login()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_login(self):
        self.login_frame = tk.Frame(self.root, padx=28, pady=28)
        self.login_frame.pack(expand=True)
        tk.Label(
            self.login_frame,
            text="Secure Communication",
            font=("Segoe UI", 18, "bold"),
        ).pack(pady=(0, 18))
        tk.Label(self.login_frame, text="Username").pack(anchor="w")
        self.username_entry = tk.Entry(self.login_frame, width=34)
        self.username_entry.pack(pady=(4, 12))
        tk.Label(self.login_frame, text="Password").pack(anchor="w")
        self.password_entry = tk.Entry(self.login_frame, width=34, show="*")
        self.password_entry.pack(pady=(4, 16))
        self.username_entry.bind("<Return>", lambda _event: self._connect())
        self.password_entry.bind("<Return>", lambda _event: self._connect())
        self.login_button = tk.Button(
            self.login_frame, text="Sign in", width=18, command=self._connect
        )
        self.login_button.pack()
        self.login_status = tk.Label(
            self.login_frame, text="", fg="#a00000", wraplength=360
        )
        self.login_status.pack(pady=(12, 0))
        self.username_entry.focus_set()

    def _connect(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.login_status.config(text="Enter your username and password.")
            return
        self.login_button.config(state="disabled")
        self.login_status.config(text="Connecting…", fg="#444444")
        threading.Thread(
            target=self._connect_worker,
            args=(username, password),
            daemon=True,
        ).start()

    def _connect_worker(self, username: str, password: str):
        try:
            self.client.connect(username=username, password=password)
            self.root.after(0, lambda: self._show_chat(username))
        except Exception as error:
            self.root.after(0, lambda message=str(error): self._login_failed(message))

    def _login_failed(self, message: str):
        self.login_button.config(state="normal")
        self.login_status.config(text=message, fg="#a00000")

    def _show_chat(self, username: str):
        self.username = username
        self.login_frame.destroy()

        header = tk.Frame(self.root, padx=12, pady=10)
        header.pack(fill="x")
        tk.Label(
            header,
            text=f"Connected as {username}",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")
        self.status = tk.Label(
            header,
            text="TLS + authentication + integrity active",
            fg="#18733c",
        )
        self.status.pack(side="right")

        self.transcript = scrolledtext.ScrolledText(
            self.root, state="disabled", wrap="word", padx=10, pady=10
        )
        self.transcript.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        controls = tk.Frame(self.root, padx=12)
        controls.pack(fill="x", pady=(0, 6))
        tk.Button(
            controls,
            text="Decrypt user message…",
            command=self._open_decrypt_window,
        ).pack(side="left")

        options = tk.Frame(self.root, padx=12)
        options.pack(fill="x", pady=(0, 6))
        tk.Label(options, text="Recipient:").pack(side="left")
        self.recipient_entry = tk.Entry(options, width=18)
        self.recipient_entry.pack(side="left", padx=(5, 14))
        tk.Label(options, text="Shared AES key:").pack(side="left")
        self.key_var = tk.StringVar(value="key1")
        tk.OptionMenu(options, self.key_var, "key1", "key2").pack(side="left")
        self.caesar_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            options,
            text="Caesar shift 3 for server messages (demo only)",
            variable=self.caesar_var,
        ).pack(side="left", padx=(12, 0))

        composer = tk.Frame(self.root, padx=12)
        composer.pack(fill="x", pady=(0, 12))
        self.message_entry = tk.Entry(composer)
        self.message_entry.pack(fill="x", expand=True, ipady=6)
        self.message_entry.bind("<Return>", lambda _event: self._send_to_server())

        buttons = tk.Frame(self.root, padx=12)
        buttons.pack(fill="x", pady=(0, 12))
        tk.Button(
            buttons,
            text="Send to Server",
            width=18,
            command=self._send_to_server,
        ).pack(side="left")
        tk.Button(
            buttons,
            text="Send to User",
            width=18,
            command=self._send_to_user,
        ).pack(side="left", padx=(10, 0))

        self._append_line("Connected. Enter a message and choose its destination.")
        self.message_entry.focus_set()

    def _send_payload(self, outgoing: str, display: str):
        self.client.send_message(outgoing)
        self._append_line(display)
        self.message_entry.delete(0, tk.END)

    def _send_to_server(self):
        plaintext = self.message_entry.get().strip()
        if not plaintext:
            return
        if self.caesar_var.get():
            encrypted = caesar_cipher(plaintext)
            outgoing = f"@SERVER|caesar|{encrypted}"
            display = f"You to Server [Caesar]: {encrypted}"
        else:
            outgoing = f"@SERVER|plain|{plaintext}"
            display = f"You to Server: {plaintext}"
        try:
            self._send_payload(outgoing, display)
        except Exception as error:
            messagebox.showerror("Send failed", str(error))

    def _send_to_user(self):
        plaintext = self.message_entry.get().strip()
        recipient = self.recipient_entry.get().strip()
        if not plaintext:
            return
        if not recipient:
            messagebox.showerror("Recipient required", "Enter the other user's username.")
            return
        if recipient.casefold() == self.username.casefold():
            messagebox.showerror("Invalid recipient", "Choose another user's username.")
            return
        try:
            token = encrypt_with_shared_key(plaintext, self.key_var.get())
            self._send_payload(
                f"@USER|{recipient}|{token}",
                f"You to {recipient} [AES-GCM]: {token}",
            )
        except Exception as error:
            messagebox.showerror("Send failed", str(error))

    def _open_decrypt_window(self):
        window = tk.Toplevel(self.root)
        window.title("Decrypt User Message")
        window.geometry("620x440")
        window.transient(self.root)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)
        window.rowconfigure(4, weight=1)

        tk.Label(
            window,
            text="Paste an ENC2 message token from the chat transcript.",
            wraplength=570,
            justify="left",
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))
        token_box = scrolledtext.ScrolledText(window, height=7, wrap="word")
        token_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)
        status = tk.Label(window, text="", fg="#a00000", anchor="w")
        status.grid(row=2, column=0, sticky="ew", padx=12, pady=4)
        plaintext_box = scrolledtext.ScrolledText(
            window, height=7, wrap="word", state="disabled"
        )
        plaintext_box.grid(row=4, column=0, sticky="nsew", padx=12, pady=6)

        def decrypt_from_window():
            pasted = token_box.get("1.0", "end").strip()
            marker = pasted.find("ENC2:")
            if marker >= 0:
                pasted = pasted[marker:].split()[0]
            try:
                decoded = decrypt_with_shared_key(pasted)
            except Exception as error:
                status.config(text=str(error), fg="#a00000")
                return
            plaintext_box.config(state="normal")
            plaintext_box.delete("1.0", "end")
            plaintext_box.insert("1.0", decoded)
            plaintext_box.config(state="disabled")
            status.config(text="Message decrypted.", fg="#18733c")

        tk.Button(window, text="Decrypt", command=decrypt_from_window).grid(
            row=3, column=0, sticky="e", padx=12, pady=4
        )

    def _on_message(self, message: str):
        if message.startswith("Server: @SERVER_REPLY|caesar|"):
            ciphertext = message.split("|", 2)[2]
            display = f"Server: {caesar_decipher(ciphertext)}"
        elif message.startswith("Server: @SERVER_REPLY|plain|"):
            display = f"Server: {message.split('|', 2)[2]}"
        elif message.startswith("@USER_MESSAGE|"):
            _, sender, token = message.split("|", 2)
            display = f"{sender} [AES-GCM]: {token}"
        else:
            display = message
        self.root.after(0, lambda text=display: self._append_line(text))

    def _on_disconnect(self):
        self.root.after(0, self._mark_disconnected)

    def _mark_disconnected(self):
        if hasattr(self, "status"):
            self.status.config(text="Disconnected", fg="#a00000")
            self._append_line("Connection closed.")

    def _append_line(self, message: str):
        if not hasattr(self, "transcript"):
            return
        self.transcript.config(state="normal")
        self.transcript.insert(tk.END, message + "\n")
        self.transcript.see(tk.END)
        self.transcript.config(state="disabled")

    def _close(self):
        self.client.disconnect()
        self.root.destroy()


def main():
    root = tk.Tk()
    CommunicationApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
