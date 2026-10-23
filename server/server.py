"""TLS chat server with authentication, integrity checks, and user-message relay."""

import json
import logging
import socket
import ssl
import threading

from config import (
    CONNECTION_TIMEOUT,
    LOG_FILE,
    MAX_CLIENTS,
    SERVER_HOST,
    SERVER_PORT,
    initialize_directories,
)
from security.auth import (
    load_challenge_material,
    new_challenge,
    verify_proof,
)
from security.integrity import (
    derive_message_key,
    message_mac,
    verify_message,
)
from security.tls_manager import create_server_context
from server.responses import generate_response


_clients = {}
_clients_lock = threading.Lock()


def caesar_cipher(text, shift=3):
    """Demo-only letter shift for server messages; this is not secure encryption."""
    result = []

    for character in text:
        if "a" <= character <= "z":
            result.append(
                chr((ord(character) - ord("a") + shift) % 26 + ord("a"))
            )
        elif "A" <= character <= "Z":
            result.append(
                chr((ord(character) - ord("A") + shift) % 26 + ord("A"))
            )
        else:
            result.append(character)

    return "".join(result)


def caesar_decipher(text, shift=3):
    """Reverse the demo-only Caesar shift."""
    return caesar_cipher(text, -shift)


class ClientSession:
    """State for one authenticated client connection."""

    def __init__(self, username, connection, reader, message_key):
        self.username = username
        self.connection = connection
        self.reader = reader
        self.message_key = message_key
        self.receive_sequence = 1
        self.send_sequence = 1
        self.send_lock = threading.Lock()


def configure_logging():
    """Set up logging to both the configured log file and the terminal."""
    initialize_directories()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def _send_json(connection, payload):
    """Send one JSON object followed by a newline."""
    data = json.dumps(payload) + "\n"
    connection.sendall(data.encode("utf-8"))


def _read_json(reader):
    """Read one newline-delimited JSON object."""
    line = reader.readline()

    if not line:
        raise ConnectionError("Client disconnected during connection setup.")

    packet = json.loads(line)

    if not isinstance(packet, dict):
        raise ValueError("Invalid client setup packet.")

    return packet


def authenticate(connection, reader):
    """Authenticate a username using a fresh server challenge."""
    _send_json(connection, {"type": "auth_username"})

    request = _read_json(reader)

    if (
        request.get("type") != "username"
        or not isinstance(request.get("username"), str)
    ):
        raise PermissionError("Authentication failed.")

    username = request["username"]

    salt, iterations, verifier, user_exists = load_challenge_material(username)
    nonce = new_challenge()

    _send_json(
        connection,
        {
            "type": "auth_challenge",
            "salt": salt,
            "iterations": iterations,
            "nonce": nonce,
        },
    )

    response = _read_json(reader)

    if response.get("type") == "auth_response":
        proof = response.get("proof", "")
    else:
        proof = ""

    if not user_exists or not verify_proof(verifier, nonce, proof):
        _send_json(
            connection,
            {
                "type": "auth_result",
                "ok": False,
                "message": "Authentication failed.",
            },
        )
        raise PermissionError("Authentication failed.")

    _send_json(
        connection,
        {
            "type": "auth_result",
            "ok": True,
            "message": "Authenticated.",
        },
    )

    return username, verifier


def send_protected(session, packet_type, message):
    """Send one server-to-client packet protected with a sequence and HMAC."""
    with session.send_lock:
        sequence = session.send_sequence

        packet = {
            "type": packet_type,
            "sequence": sequence,
            "message": message,
            "mac": message_mac(
                session.message_key,
                "server-to-client",
                sequence,
                message,
            ),
        }

        data = json.dumps(packet) + "\n"
        session.connection.sendall(data.encode("utf-8"))
        session.send_sequence += 1


def deliver_user_message(sender, recipient_name, token):
    """Forward an encrypted message token to connected clients matching a username."""
    if not token.startswith("ENC2:"):
        send_protected(sender, "reply", "Invalid encrypted user message.")
        return

    with _clients_lock:
        recipients = [
            session
            for session in _clients.values()
            if session.username.casefold() == recipient_name.casefold()
        ]

    if not recipients:
        send_protected(
            sender,
            "reply",
            f"User {recipient_name} is not online.",
        )
        return

    relay_packet = f"@USER_MESSAGE|{sender.username}|{token}"

    for recipient in recipients:
        try:
            send_protected(recipient, "chat", relay_packet)
        except (ConnectionError, OSError, ssl.SSLError) as error:
            logging.info(
                "Could not deliver to %s: %s",
                recipient.username,
                error,
            )

    send_protected(
        sender,
        "reply",
        f"Encrypted message sent to {recipient_name}.",
    )


def process_client_message(session, message):
    """Route server-directed messages and user-directed messages."""
    if message.startswith("@USER|"):
        parts = message.split("|", 2)

        if len(parts) != 3 or not parts[1]:
            send_protected(session, "reply", "Invalid user-message format.")
            return

        recipient_name = parts[1]
        encrypted_token = parts[2]
        deliver_user_message(session, recipient_name, encrypted_token)
        return

    if message.startswith("@SERVER|"):
        parts = message.split("|", 2)

        if len(parts) != 3 or parts[1] not in {"plain", "caesar"}:
            send_protected(session, "reply", "Invalid server-message format.")
            return

        mode = parts[1]
        content = parts[2]

        if mode == "caesar":
            plaintext = caesar_decipher(content)
        else:
            plaintext = content

        response = generate_response(plaintext)

        if mode == "caesar":
            response = f"@SERVER_REPLY|caesar|{caesar_cipher(response)}"
        else:
            response = f"@SERVER_REPLY|plain|{response}"

        send_protected(session, "reply", response)
        return

    # Support a regular message by treating it as a plain server-directed message.
    response = generate_response(message)
    send_protected(
        session,
        "reply",
        f"@SERVER_REPLY|plain|{response}",
    )


def handle_client(raw_socket, client_address, tls_context):
    """Wrap a client socket in TLS, authenticate it, then handle its messages."""
    session = None

    try:
        raw_socket.settimeout(CONNECTION_TIMEOUT)

        with tls_context.wrap_socket(raw_socket, server_side=True) as client_socket:
            client_socket.settimeout(CONNECTION_TIMEOUT)
            reader = client_socket.makefile("r", encoding="utf-8")

            username, verifier = authenticate(client_socket, reader)
            message_key = derive_message_key(verifier)

            session = ClientSession(
                username,
                client_socket,
                reader,
                message_key,
            )

            with _clients_lock:
                _clients[id(session)] = session
                online_count = len(_clients)

            client_socket.settimeout(None)

            logging.info(
                "Authenticated TLS client %s from %s; %d client(s) online",
                session.username,
                client_address,
                online_count,
            )

            while True:
                line = reader.readline()

                if not line:
                    break

                packet = json.loads(line)

                if not isinstance(packet, dict) or packet.get("type") != "message":
                    raise ValueError("Unexpected message packet.")

                sequence = packet.get("sequence")
                message = packet.get("message")

                if (
                    sequence != session.receive_sequence
                    or not isinstance(message, str)
                ):
                    raise ValueError("Invalid message sequence or content.")

                # Verify with this client's authenticated session key.
                if not verify_message(
                    session.message_key,
                    "client-to-server",
                    sequence,
                    message,
                    packet.get("mac", ""),
                ):
                    raise PermissionError("Message integrity check failed.")

                session.receive_sequence += 1

                logging.info(
                    "Message received from %s (%d characters)",
                    session.username,
                    len(message),
                )

                process_client_message(session, message)

    except (
        ssl.SSLError,
        ConnectionError,
        OSError,
        ValueError,
        PermissionError,
        TypeError,
    ) as error:
        logging.info("Connection ended for %s: %s", client_address, error)

    finally:
        if session is not None:
            with _clients_lock:
                _clients.pop(id(session), None)

            logging.info("Client %s disconnected", session.username)

        try:
            raw_socket.close()
        except OSError:
            pass


def start_server():
    """Start the TLS server and accept client connections."""
    configure_logging()
    tls_context = create_server_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(MAX_CLIENTS)

        logging.info(
            "TLS/authenticated relay server listening on %s:%s",
            SERVER_HOST,
            SERVER_PORT,
        )

        try:
            while True:
                client_socket, client_address = server_socket.accept()

                thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address, tls_context),
                    daemon=True,
                )
                thread.start()

        except KeyboardInterrupt:
            logging.info("Server shutdown requested.")


if __name__ == "__main__":
    start_server()