# ============================================================
# END-TO-END ENCRYPTED CHAT SYSTEM
# Subject: Data Encryption and Network Security
# Concepts Used: RSA, AES-CBC, Hybrid Encryption, SHA-256, E2EE
# ============================================================
"""
client.py
=========
Tkinter GUI client for the E2EE Chat System.

Role in the system:
  - Provides a Login/Register screen for user authentication.
  - On successful login, generates an RSA-2048 key pair for the session.
  - Connects to the server, registers the user and exchanges public keys.
  - Encrypts outgoing messages using the recipient's RSA public key + a fresh AES key.
  - Decrypts incoming messages using its own RSA private key + the bundled AES key.
  - Displays decrypted messages in a color-coded chat window.

Subject: Data Encryption and Network Security
Concepts: RSA key exchange, AES-CBC encryption, Hybrid Encryption, E2EE,
          SHA-256 authentication, length-prefixed TCP messaging
"""

import socket
import threading
import json
import struct
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

import auth
import crypto_utils

# ─────────────────────────────────────────────────────────────────────────────
# Server connection settings — must match server.py
# ─────────────────────────────────────────────────────────────────────────────
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 55000


# ─────────────────────────────────────────────────────────────────────────────
# Low-Level TCP Messaging (mirrors server.py exactly)
# ─────────────────────────────────────────────────────────────────────────────

def send_message(conn: socket.socket, data: dict) -> None:
    """
    Send a JSON-encoded dict over a TCP socket using a 4-byte length prefix.

    Length-prefixed framing solves TCP stream fragmentation:
      TCP is a byte-stream protocol — it may split or merge packets.
      Prefixing each message with its length lets the receiver reconstruct
      complete messages regardless of how TCP delivers the bytes.

    Args:
        conn (socket.socket): The connected server socket.
        data (dict):          The message to serialize and send.
    """
    payload = json.dumps(data).encode('utf-8')
    header = struct.pack('>I', len(payload))
    conn.sendall(header + payload)


def receive_message(conn: socket.socket) -> dict | None:
    """
    Receive a length-prefixed JSON message from the server.

    Args:
        conn (socket.socket): The server socket to read from.

    Returns:
        dict | None: Parsed message, or None if the connection was closed.
    """
    raw_len = _recv_exact(conn, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    raw_payload = _recv_exact(conn, msg_len)
    if raw_payload is None:
        return None
    return json.loads(raw_payload.decode('utf-8'))


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    """
    Read exactly n bytes from a socket, handling partial reads gracefully.

    Args:
        conn (socket.socket): Socket to read from.
        n (int):              Number of bytes to read.

    Returns:
        bytes | None: Exactly n bytes, or None if the connection closed.
    """
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# Auth Screen (Window 1)
# ─────────────────────────────────────────────────────────────────────────────

class AuthScreen:
    """
    Tkinter login/register window.

    Allows the user to either register a new account (SHA-256 hashed)
    or log in with existing credentials before accessing the chat.
    """

    def __init__(self, root: tk.Tk, on_auth_success):
        """
        Build the authentication UI.

        Args:
            root (tk.Tk):        The root Tkinter window.
            on_auth_success:     Callback(username) invoked on successful auth.
        """
        self.root = root
        self.on_auth_success = on_auth_success

        root.title("E2EE Chat — Login / Register")
        root.resizable(False, False)
        root.configure(bg="#1e1e2e")

        self._build_ui()

    def _build_ui(self) -> None:
        """Construct all widgets for the authentication screen."""
        frame = tk.Frame(self.root, bg="#1e1e2e", padx=40, pady=30)
        frame.pack()

        # Title
        tk.Label(
            frame, text="🔒 E2EE Chat System",
            font=("Helvetica", 18, "bold"),
            fg="#cba6f7", bg="#1e1e2e"
        ).grid(row=0, column=0, columnspan=2, pady=(0, 6))

        tk.Label(
            frame, text="Data Encryption & Network Security",
            font=("Helvetica", 9, "italic"),
            fg="#6c7086", bg="#1e1e2e"
        ).grid(row=1, column=0, columnspan=2, pady=(0, 20))

        # Username field
        tk.Label(frame, text="Username", fg="#cdd6f4", bg="#1e1e2e",
                 font=("Helvetica", 11)).grid(row=2, column=0, sticky="w", pady=4)
        self.username_var = tk.StringVar()
        tk.Entry(
            frame, textvariable=self.username_var, width=28,
            bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief="flat", font=("Helvetica", 11)
        ).grid(row=2, column=1, padx=(10, 0), pady=4)

        # Password field
        tk.Label(frame, text="Password", fg="#cdd6f4", bg="#1e1e2e",
                 font=("Helvetica", 11)).grid(row=3, column=0, sticky="w", pady=4)
        self.password_var = tk.StringVar()
        tk.Entry(
            frame, textvariable=self.password_var, show='*', width=28,
            bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief="flat", font=("Helvetica", 11)
        ).grid(row=3, column=1, padx=(10, 0), pady=4)

        # Buttons
        btn_frame = tk.Frame(frame, bg="#1e1e2e")
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(18, 6))

        tk.Button(
            btn_frame, text="Login", command=self._login,
            bg="#89b4fa", fg="#1e1e2e", font=("Helvetica", 11, "bold"),
            relief="flat", padx=20, pady=6, cursor="hand2"
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            btn_frame, text="Register", command=self._register,
            bg="#a6e3a1", fg="#1e1e2e", font=("Helvetica", 11, "bold"),
            relief="flat", padx=20, pady=6, cursor="hand2"
        ).pack(side=tk.LEFT, padx=8)

        # Status label (shows success/error messages)
        self.status_label = tk.Label(
            frame, text="", fg="#f38ba8", bg="#1e1e2e",
            font=("Helvetica", 10, "italic"), wraplength=300
        )
        self.status_label.grid(row=5, column=0, columnspan=2, pady=(8, 0))

    def _get_inputs(self) -> tuple:
        """Extract and strip username/password from the entry fields."""
        return self.username_var.get().strip(), self.password_var.get()

    def _set_status(self, message: str, ok: bool = False) -> None:
        """
        Display a status message below the buttons.

        Args:
            message (str): Text to display.
            ok (bool):     True = green (success); False = red (error).
        """
        color = "#a6e3a1" if ok else "#f38ba8"
        self.status_label.config(text=message, fg=color)

    def _register(self) -> None:
        """
        Handle the Register button click.

        Calls auth.register_user which SHA-256 hashes the password before storage.
        SHA-256 one-way hash protects passwords at rest.
        """
        username, password = self._get_inputs()
        success, message = auth.register_user(username, password)
        self._set_status(message, ok=success)

    def _login(self) -> None:
        """
        Handle the Login button click.

        Calls auth.login_user which hashes the entered password and compares
        it against the stored SHA-256 hash. On success, triggers the chat window.
        """
        username, password = self._get_inputs()
        success, message = auth.login_user(username, password)
        if success:
            self._set_status(message, ok=True)
            self.root.after(500, lambda: self.on_auth_success(username))
        else:
            self._set_status(message, ok=False)


# ─────────────────────────────────────────────────────────────────────────────
# Chat Screen (Window 2)
# ─────────────────────────────────────────────────────────────────────────────

class ChatScreen:
    """
    Tkinter chat window — opened after successful authentication.

    Responsibilities:
      1. Generate an RSA-2048 key pair for this session.
      2. Connect to the server and register (send username + public key).
      3. Receive other clients' public keys and maintain a local pubkey registry.
      4. Allow the user to select a recipient, type a message, and send it encrypted.
      5. Receive encrypted bundles and decrypt them for display.
      6. Show live online users list.
    """

    def __init__(self, root: tk.Tk, username: str):
        """
        Initialize the chat screen and connect to the server.

        Args:
            root (tk.Tk):    The Tkinter root window (will be reconfigured).
            username (str):  The authenticated username for this session.
        """
        self.root = root
        self.username = username
        self.sock = None
        self.connected = False

        # RSA-2048 key pair for this session
        # RSA provides asymmetric encryption for key exchange
        self.private_key_pem, self.public_key_pem = crypto_utils.generate_rsa_keypair()

        # Registry of other users' public keys: { username: pem_string }
        # Public key exchange enables secure session key establishment
        self.peer_pubkeys: dict = {}

        self._build_ui()
        self._connect_to_server()

    # ── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Build the full chat window layout."""
        self.root.title(f"E2EE Chat — Logged in as {self.username}")
        self.root.configure(bg="#1e1e2e")
        self.root.geometry("860x600")
        self.root.resizable(True, True)

        # ── Top bar: encryption status indicator ─────────────────────────────
        top_bar = tk.Frame(self.root, bg="#181825", pady=6)
        top_bar.pack(fill=tk.X)

        tk.Label(
            top_bar,
            text=f"🔒  All messages are End-to-End Encrypted  |  Logged in as: {self.username}",
            font=("Helvetica", 10, "bold"),
            fg="#a6e3a1", bg="#181825"
        ).pack()

        # ── Main content frame ────────────────────────────────────────────────
        content = tk.Frame(self.root, bg="#1e1e2e")
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 0))

        # ── Left panel: Online Users ──────────────────────────────────────────
        left_panel = tk.Frame(content, bg="#181825", width=160)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        left_panel.pack_propagate(False)

        tk.Label(
            left_panel, text="Online Users",
            font=("Helvetica", 11, "bold"),
            fg="#cba6f7", bg="#181825"
        ).pack(pady=(10, 4))

        self.users_listbox = tk.Listbox(
            left_panel,
            bg="#313244", fg="#cdd6f4",
            selectbackground="#45475a", selectforeground="#cdd6f4",
            font=("Helvetica", 10), relief="flat",
            activestyle="none", borderwidth=0
        )
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 10))
        self.users_listbox.bind("<<ListboxSelect>>", self._on_user_select)

        # ── Center panel: Chat history ────────────────────────────────────────
        center_panel = tk.Frame(content, bg="#1e1e2e")
        center_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_display = scrolledtext.ScrolledText(
            center_panel,
            state=tk.DISABLED,
            bg="#181825", fg="#cdd6f4",
            font=("Courier", 10),
            relief="flat", padx=10, pady=8,
            wrap=tk.WORD
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Color tags for message types
        # Sent messages: blue; Received: green; System/error: grey italic
        self.chat_display.tag_config("sent",     foreground="#89b4fa")
        self.chat_display.tag_config("received", foreground="#a6e3a1")
        self.chat_display.tag_config("system",   foreground="#6c7086", font=("Courier", 9, "italic"))
        self.chat_display.tag_config("error",    foreground="#f38ba8", font=("Courier", 9, "italic"))

        # ── Bottom panel: Send controls ───────────────────────────────────────
        bottom = tk.Frame(self.root, bg="#181825", pady=8)
        bottom.pack(fill=tk.X, padx=10, pady=(6, 8))

        tk.Label(
            bottom, text="To:", fg="#cdd6f4", bg="#181825",
            font=("Helvetica", 10)
        ).pack(side=tk.LEFT, padx=(0, 4))

        self.recipient_var = tk.StringVar(value="(select user)")
        self.recipient_menu = ttk.OptionMenu(bottom, self.recipient_var, "(select user)")
        self.recipient_menu.pack(side=tk.LEFT, padx=(0, 10))

        self.message_entry = tk.Entry(
            bottom, bg="#313244", fg="#cdd6f4",
            insertbackground="#cdd6f4",
            font=("Helvetica", 11), relief="flat"
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.message_entry.bind("<Return>", lambda e: self._send_message())

        tk.Button(
            bottom, text="Send 🔒", command=self._send_message,
            bg="#cba6f7", fg="#1e1e2e",
            font=("Helvetica", 11, "bold"),
            relief="flat", padx=14, pady=4, cursor="hand2"
        ).pack(side=tk.LEFT)

    # ── Server Connection ─────────────────────────────────────────────────────

    def _connect_to_server(self) -> None:
        """
        Establish a TCP connection to the chat server and register the client.

        Registration sends:
          - The username (so the server knows who this socket belongs to).
          - The RSA public key (so the server can relay it to peers).

        The RSA PRIVATE KEY is never sent — it remains on this machine only.
        E2EE: Only sender and recipient hold keys — server is a blind relay.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            self.connected = True

            # Send registration: username + RSA public key
            # Public key exchange enables secure session key establishment
            send_message(self.sock, {
                "type": "register",
                "username": self.username,
                "pubkey": self.public_key_pem   # Public key only — NEVER the private key
            })

            # Start background thread to listen for incoming server messages
            listener = threading.Thread(target=self._listen_to_server, daemon=True)
            listener.start()

            self._append_chat("Connected to E2EE Chat Server. Waiting for peers...\n", "system")

        except ConnectionRefusedError:
            messagebox.showerror(
                "Connection Error",
                f"Could not connect to server at {SERVER_HOST}:{SERVER_PORT}.\n"
                "Make sure server.py is running first."
            )
            self.connected = False
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.connected = False

    # ── Background Listener Thread ────────────────────────────────────────────

    def _listen_to_server(self) -> None:
        """
        Background thread: continuously read and dispatch messages from the server.

        Runs until the connection is closed or an error occurs.
        All UI updates are marshalled back to the main thread via root.after().
        """
        while self.connected:
            try:
                msg = receive_message(self.sock)
                if msg is None:
                    break
                self.root.after(0, self._handle_server_message, msg)
            except Exception:
                break

        self.connected = False
        self.root.after(0, self._append_chat, "Disconnected from server.\n", "error")

    def _handle_server_message(self, msg: dict) -> None:
        """
        Dispatch an incoming server message to the appropriate handler.

        Message types:
          - "pubkey"      → store a peer's RSA public key
          - "user_list"   → update the online-users panel and recipient dropdown
          - "message"     → decrypt and display an incoming chat message
          - "register_ok" → show the server's welcome confirmation
          - "error"       → display an error in the chat window

        Args:
            msg (dict): Parsed JSON message from the server.
        """
        msg_type = msg.get("type")

        if msg_type == "pubkey":
            # Store the peer's public key for future encryption
            # RSA provides asymmetric encryption for key exchange
            peer_name = msg.get("username")
            peer_pubkey = msg.get("pubkey")
            if peer_name and peer_pubkey:
                self.peer_pubkeys[peer_name] = peer_pubkey
                self._append_chat(
                    f"  ← Received public key from '{peer_name}' (RSA-2048 key exchange)\n",
                    "system"
                )

        elif msg_type == "user_list":
            users = msg.get("users", [])
            self._update_user_list(users)

        elif msg_type == "message":
            self._decrypt_and_display(msg)

        elif msg_type == "register_ok":
            self._append_chat(f"  ✓ {msg.get('message', 'Registered')}\n", "system")

        elif msg_type == "error":
            self._append_chat(f"  ✗ Server: {msg.get('message', 'Unknown error')}\n", "error")

    # ── Sending Messages ──────────────────────────────────────────────────────

    def _send_message(self) -> None:
        """
        Encrypt the typed message and send it to the server for relay.

        Encryption flow (hybrid encryption):
          1. Look up the recipient's RSA public key from the local registry.
          2. Generate a fresh 16-byte AES session key.
          3. Encrypt the message with AES-128-CBC (fresh IV per message).
          4. Encrypt the AES key with the recipient's RSA public key (OAEP).
          5. Bundle all fields (base64-encoded) into a JSON message and send.

        Hybrid encryption: RSA for key exchange, AES for data encryption.
        The server receives this bundle and forwards it — it cannot decrypt it.
        E2EE: Only sender and recipient hold keys — server is a blind relay.
        """
        if not self.connected:
            messagebox.showwarning("Not Connected", "You are not connected to the server.")
            return

        recipient = self.recipient_var.get()
        if not recipient or recipient == "(select user)":
            messagebox.showwarning("No Recipient", "Please select a recipient from the dropdown.")
            return

        if recipient not in self.peer_pubkeys:
            messagebox.showwarning(
                "No Public Key",
                f"No public key found for '{recipient}'.\n"
                "They may not be connected yet."
            )
            return

        plaintext = self.message_entry.get().strip()
        if not plaintext:
            return

        try:
            # ── Hybrid encryption ─────────────────────────────────────────────
            # Step 1: Retrieve the recipient's RSA public key
            recipient_pubkey = self.peer_pubkeys[recipient]

            # Steps 2-4: Generate AES key, encrypt message, encrypt AES key
            # Hybrid encryption: RSA for key exchange, AES for data encryption
            encrypted_bundle = crypto_utils.hybrid_encrypt(plaintext, recipient_pubkey)

            # Step 5: Build and send the full JSON message bundle
            bundle = {
                "type": "message",
                "sender": self.username,
                "recipient": recipient,
                # RSA-encrypted AES key (base64) — only recipient's private key can unwrap this
                "encrypted_aes_key": encrypted_bundle["encrypted_aes_key"],
                # Random IV (base64) — required for CBC decryption; fresh each message
                # Random IV prevents ciphertext pattern analysis (semantic security)
                "iv": encrypted_bundle["iv"],
                # AES-CBC ciphertext (base64) — the actual encrypted message content
                "ciphertext": encrypted_bundle["ciphertext"],
            }

            send_message(self.sock, bundle)

            # Display the sent message locally in the chat window
            timestamp = datetime.now().strftime("%H:%M:%S")
            self._append_chat(
                f"[{timestamp}] [You] → {recipient}: {plaintext}\n",
                "sent"
            )
            self.message_entry.delete(0, tk.END)

        except Exception as e:
            self._append_chat(f"  ✗ Encryption/send error: {e}\n", "error")

    # ── Receiving Messages ────────────────────────────────────────────────────

    def _decrypt_and_display(self, msg: dict) -> None:
        """
        Decrypt an incoming encrypted message bundle and display it.

        Decryption flow:
          1. Base64-decode the encrypted_aes_key, iv, and ciphertext fields.
          2. Decrypt the AES key using THIS client's RSA PRIVATE KEY (OAEP).
          3. Decrypt the ciphertext using the recovered AES key + IV (AES-CBC).
          4. Display the plaintext message in the chat window.

        E2EE guarantee: Only this client (the intended recipient) can perform
        Step 2, because only this client holds the matching private key.
        The server forwarded the bundle without being able to read the content.

        Args:
            msg (dict): The encrypted message bundle from the server.
        """
        sender = msg.get("sender", "Unknown")
        encrypted_aes_key_b64 = msg.get("encrypted_aes_key", "")
        iv_b64 = msg.get("iv", "")
        ciphertext_b64 = msg.get("ciphertext", "")

        try:
            # Perform hybrid decryption using our RSA private key
            # E2EE: Only sender and recipient hold keys — server is a blind relay
            plaintext = crypto_utils.hybrid_decrypt(
                encrypted_aes_key_b64,
                iv_b64,
                ciphertext_b64,
                self.private_key_pem   # Our private key — never shared with the server
            )

            timestamp = datetime.now().strftime("%H:%M:%S")
            self._append_chat(
                f"[{timestamp}] {sender} → [You]: {plaintext}\n",
                "received"
            )
        except Exception as e:
            self._append_chat(
                f"  ✗ Failed to decrypt message from '{sender}': {e}\n",
                "error"
            )

    # ── UI Helpers ────────────────────────────────────────────────────────────

    def _append_chat(self, text: str, tag: str) -> None:
        """
        Append a line of text to the (read-only) chat display widget.

        Args:
            text (str): The text to append.
            tag (str):  One of "sent", "received", "system", "error" — controls colour.
        """
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text, tag)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def _update_user_list(self, users: list) -> None:
        """
        Refresh the Online Users listbox and the recipient OptionMenu.

        Called whenever the server broadcasts an updated user list
        (on connect or disconnect of any client).

        Args:
            users (list[str]): Usernames of all currently connected clients.
        """
        # Update the listbox
        self.users_listbox.delete(0, tk.END)
        for user in users:
            display = f"● {user}" if user != self.username else f"● {user} (you)"
            self.users_listbox.insert(tk.END, display)

        # Rebuild the recipient dropdown with peers (exclude self)
        peers = [u for u in users if u != self.username]

        menu = self.recipient_menu["menu"]
        menu.delete(0, "end")
        if peers:
            for peer in peers:
                menu.add_command(
                    label=peer,
                    command=lambda p=peer: self.recipient_var.set(p)
                )
            if self.recipient_var.get() not in peers:
                self.recipient_var.set(peers[0])
        else:
            menu.add_command(label="(no other users online)")
            self.recipient_var.set("(select user)")

    def _on_user_select(self, event) -> None:
        """
        When the user clicks a name in the Online Users listbox,
        set that user as the current recipient in the dropdown.
        """
        selection = self.users_listbox.curselection()
        if not selection:
            return
        item = self.users_listbox.get(selection[0])
        # Strip the "● " prefix and " (you)" suffix
        username = item.lstrip("● ").replace(" (you)", "").strip()
        if username != self.username:
            self.recipient_var.set(username)

    def on_close(self) -> None:
        """
        Send a disconnect signal to the server and clean up before closing.
        Called when the user closes the chat window.
        """
        if self.connected and self.sock:
            try:
                send_message(self.sock, {"type": "disconnect", "username": self.username})
                time.sleep(0.2)
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Launch the E2EE Chat client application.

    Flow:
      1. Show the Auth screen (Login/Register).
      2. On successful authentication, tear down the auth widgets and
         replace them with the Chat screen.
    """
    root = tk.Tk()
    root.resizable(False, False)

    chat_screen_ref = [None]   # Mutable container so the closure can reference it

    def on_auth_success(username: str) -> None:
        """
        Transition from the Auth screen to the Chat screen.

        Args:
            username (str): The authenticated username.
        """
        # Destroy all existing widgets (the auth form)
        for widget in root.winfo_children():
            widget.destroy()

        # Allow the window to resize for the chat layout
        root.resizable(True, True)

        # Create the chat screen
        chat = ChatScreen(root, username)
        chat_screen_ref[0] = chat

        # Hook the close button to our graceful disconnect
        root.protocol("WM_DELETE_WINDOW", chat.on_close)

    # Show the login/register screen first
    AuthScreen(root, on_auth_success)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == '__main__':
    main()
