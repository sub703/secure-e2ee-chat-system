"""
server.py
=========
Multi-threaded TCP socket server for the E2EE Chat System.

Role in the system:
  - Accepts TCP connections from multiple clients on port 55000.
  - Manages a registry of connected clients and their RSA public keys.
  - Relays encrypted message bundles between clients WITHOUT decrypting them.
  - Demonstrates true E2EE: the server handles only ciphertext and metadata.

Subject: Data Encryption and Network Security
Concepts: E2EE (server as blind relay), RSA public key distribution, TCP sockets,
          length-prefixed messaging, multi-threading

System Architecture:
  [Alice Client]                    [Server]                   [Bob Client]
  Generate RSA keypair              Stores public keys          Generate RSA keypair
  Send public key ────────────────► Relay Bob's pubkey ───────► Receive Alice's pubkey
  Encrypt msg with Bob's pubkey ──► Forward ciphertext ─────────► Decrypt with Bob's privkey
  (Server CANNOT decrypt this)
"""

import socket
import threading
import json
import struct
import logging

# ─────────────────────────────────────────────────────────────────────────────
# Logging configuration — gives each server log a timestamp and severity level
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

HOST = '0.0.0.0'   # Listen on all network interfaces
PORT = 55000        # Port number agreed upon between server and clients

# ─────────────────────────────────────────────────────────────────────────────
# Connected clients registry
# Structure: { username: {"conn": socket, "pubkey": PEM string, "addr": tuple} }
#
# The server stores only public keys — private keys NEVER leave the client.
# Public key exchange enables secure session key establishment.
# ─────────────────────────────────────────────────────────────────────────────
clients: dict = {}
clients_lock = threading.Lock()   # Thread-safe access to the shared clients dict


# ─────────────────────────────────────────────────────────────────────────────
# Length-Prefixed TCP Messaging
# ─────────────────────────────────────────────────────────────────────────────

def send_message(conn: socket.socket, data: dict) -> None:
    """
    Send a JSON message over a TCP socket using a 4-byte length prefix.

    TCP is a stream protocol — it does not preserve message boundaries.
    Without a length prefix, the receiver cannot tell where one message ends
    and the next begins (TCP fragmentation / Nagle's algorithm).

    Protocol:
      [ 4-byte big-endian uint32: message length N ][ N bytes: UTF-8 JSON payload ]

    Args:
        conn (socket.socket): The connected client socket to send to.
        data (dict):          The Python dictionary to serialize and send.
    """
    payload = json.dumps(data).encode('utf-8')
    # Pack the payload length as a 4-byte big-endian unsigned integer
    header = struct.pack('>I', len(payload))
    conn.sendall(header + payload)


def receive_message(conn: socket.socket) -> dict | None:
    """
    Receive a length-prefixed JSON message from a TCP socket.

    Reads exactly 4 header bytes first, unpacks the expected payload length N,
    then reads exactly N bytes to reconstruct the full JSON message.

    Args:
        conn (socket.socket): The client socket to read from.

    Returns:
        dict | None: Parsed JSON message, or None if the connection was closed.
    """
    # Read the 4-byte length header
    raw_len = _recv_exact(conn, 4)
    if raw_len is None:
        return None

    msg_len = struct.unpack('>I', raw_len)[0]

    # Read exactly msg_len bytes for the JSON payload
    raw_payload = _recv_exact(conn, msg_len)
    if raw_payload is None:
        return None

    return json.loads(raw_payload.decode('utf-8'))


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    """
    Read exactly n bytes from the socket, handling partial reads.

    TCP may deliver data in smaller chunks than requested (partial reads).
    This helper loops until all n bytes have been received.

    Args:
        conn (socket.socket): The socket to read from.
        n (int):              Exact number of bytes to read.

    Returns:
        bytes | None: The n bytes read, or None if the connection closed mid-read.
    """
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None   # Connection closed cleanly or unexpectedly
        buf += chunk
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# Broadcast Helpers
# ─────────────────────────────────────────────────────────────────────────────

def broadcast_user_list() -> None:
    """
    Send an updated online-user list to every connected client.

    Called whenever a client connects or disconnects so all clients can
    keep their recipient dropdown in sync.

    The payload only contains usernames, not public keys.
    Public keys are distributed separately (see handle_client).
    """
    with clients_lock:
        user_list = list(clients.keys())
        message = {"type": "user_list", "users": user_list}
        for username, info in clients.items():
            try:
                send_message(info["conn"], message)
            except Exception:
                pass   # Ignore send errors during broadcast — client may have just disconnected


def broadcast_new_pubkey(new_username: str, new_pubkey: str) -> None:
    """
    Announce a newly connected client's RSA public key to all existing clients.

    Public key exchange enables secure session key establishment.
    When Alice connects, all currently connected clients receive Alice's public key
    so they can encrypt messages addressed to Alice.

    Args:
        new_username (str): Username of the newly connected client.
        new_pubkey (str):   PEM-encoded RSA public key of the new client.
    """
    message = {
        "type": "pubkey",
        "username": new_username,
        "pubkey": new_pubkey
    }
    with clients_lock:
        for username, info in clients.items():
            if username != new_username:   # Don't send your own key to yourself
                try:
                    send_message(info["conn"], message)
                except Exception:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# Per-Client Thread
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handle all communication with a single connected client.

    This function runs in its own thread (one thread per client).
    It handles the full client lifecycle:
      1. Registration (username + RSA public key handshake).
      2. Sending existing clients' public keys to the new client.
      3. Receiving and relaying encrypted message bundles.
      4. Graceful disconnection cleanup.

    E2EE guarantee: The server reads the "recipient" field to know where to
    forward the message, but the message content ("ciphertext") is never decrypted.
    The server acts as a BLIND RELAY for ciphertext.

    Args:
        conn (socket.socket): The accepted client socket.
        addr (tuple):         The (IP, port) address of the client.
    """
    username = None
    try:
        # ── Step 1: Receive client registration message ──────────────────────
        reg_msg = receive_message(conn)
        if reg_msg is None or reg_msg.get("type") != "register":
            logger.warning(f"[{addr}] Invalid registration. Closing connection.")
            conn.close()
            return

        username = reg_msg.get("username")
        pubkey = reg_msg.get("pubkey")

        if not username or not pubkey:
            logger.warning(f"[{addr}] Missing username or pubkey in registration.")
            conn.close()
            return

        logger.info(f"[SERVER] Client '{username}' connected from {addr}")

        # ── Step 2: Register the client and send existing peers' public keys ─
        with clients_lock:
            existing_clients = {u: info for u, info in clients.items()}
            clients[username] = {"conn": conn, "pubkey": pubkey, "addr": addr}

        # Send all existing clients' public keys to the new client
        # so the new client can encrypt messages to each of them immediately.
        # Public key exchange enables secure session key establishment.
        for existing_user, info in existing_clients.items():
            send_message(conn, {
                "type": "pubkey",
                "username": existing_user,
                "pubkey": info["pubkey"]
            })

        # Broadcast the new client's public key to all existing clients
        broadcast_new_pubkey(username, pubkey)

        # Broadcast updated online-user list to everyone
        broadcast_user_list()

        # Confirm registration success to the new client
        send_message(conn, {"type": "register_ok", "message": "Connected to E2EE Chat Server"})

        # ── Step 3: Message relay loop ───────────────────────────────────────
        while True:
            msg = receive_message(conn)
            if msg is None:
                break   # Client disconnected

            msg_type = msg.get("type")

            if msg_type == "message":
                # Relay an encrypted chat message to the intended recipient
                recipient = msg.get("recipient")
                sender = msg.get("sender", username)

                # SERVER LOG: Demonstrate that the server relays ciphertext only
                # E2EE: Only sender and recipient hold keys — server is a blind relay
                ciphertext_preview = msg.get("ciphertext", "")[:30]
                logger.info(
                    f"[SERVER] Relayed encrypted message from '{sender}' to '{recipient}' "
                    f"(content hidden — ciphertext preview: {ciphertext_preview}...)"
                )

                with clients_lock:
                    recipient_info = clients.get(recipient)

                if recipient_info:
                    try:
                        # Forward the ENTIRE bundle unchanged — no decryption, no inspection
                        send_message(recipient_info["conn"], msg)
                    except Exception as e:
                        logger.error(f"[SERVER] Failed to relay message to '{recipient}': {e}")
                        send_message(conn, {
                            "type": "error",
                            "message": f"Could not deliver message to '{recipient}'."
                        })
                else:
                    logger.warning(f"[SERVER] Recipient '{recipient}' not found or offline.")
                    send_message(conn, {
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })

            elif msg_type == "disconnect":
                logger.info(f"[SERVER] Client '{username}' signaled disconnect.")
                break

            else:
                logger.warning(f"[SERVER] Unknown message type from '{username}': {msg_type}")

    except Exception as e:
        logger.error(f"[SERVER] Error handling client '{username}' at {addr}: {e}")

    finally:
        # ── Step 4: Clean up on disconnect ───────────────────────────────────
        if username:
            with clients_lock:
                clients.pop(username, None)
            logger.info(f"[SERVER] Client '{username}' disconnected.")
            broadcast_user_list()

        try:
            conn.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Server Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def start_server() -> None:
    """
    Start the E2EE Chat Server and begin accepting client connections.

    Creates a TCP socket, binds it to HOST:PORT, and enters an accept loop.
    Each accepted connection is handled by a dedicated thread (handle_client).

    The server uses SO_REUSEADDR so it can restart quickly without waiting
    for the OS to release the port.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # SO_REUSEADDR prevents "Address already in use" errors after a crash/restart
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen(10)   # Allow up to 10 pending connections in the queue

    logger.info("=" * 60)
    logger.info("  E2EE Chat Server — Data Encryption and Network Security")
    logger.info("=" * 60)
    logger.info(f"[SERVER] Listening on {HOST}:{PORT}")
    logger.info("[SERVER] The server NEVER decrypts messages — it is a blind relay.")
    logger.info("[SERVER] Waiting for clients to connect...")
    logger.info("=" * 60)

    try:
        while True:
            conn, addr = server_socket.accept()
            # Spawn a new thread for each client connection
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True   # Daemon threads exit when the main thread exits
            )
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("\n[SERVER] Shutting down gracefully.")
    finally:
        server_socket.close()


if __name__ == '__main__':
    start_server()
