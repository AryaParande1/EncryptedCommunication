"""TLS client with username-only joining and integrity-protected chat."""

import hashlib
import hmac
import json
import socket
import threading
from typing import Callable, Optional

from config import CONNECTION_TIMEOUT, SERVER_HOST, SERVER_PORT
from security.auth import derive_verifier
from security.integrity import derive_message_key, message_mac, verify_message
from security.tls_manager import create_client_context


class NetworkClient:
    """Manage one TLS connection and its chat messages."""

    def __init__(self, on_message: Optional[Callable[[str], None]] = None,
                 on_disconnect: Optional[Callable[[], None]] = None):
        self.on_message = on_message
        self.on_disconnect = on_disconnect
        self._socket = None
        self._reader = None
        self._receive_thread = None
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._connected = False
        self._username = None
        self._message_key = None
        self._send_sequence = 1
        self._receive_sequence = 1

    @property
    def connected(self) -> bool:
        with self._state_lock:
            return self._connected

    @property
    def username(self) -> Optional[str]:
        with self._state_lock:
            return self._username

    @staticmethod
    def _read_json(reader) -> dict:
        line = reader.readline()
        if not line:
            raise ConnectionError("Server closed the connection during setup.")
        packet = json.loads(line)
        if not isinstance(packet, dict):
            raise ConnectionError("Server sent an invalid protocol response.")
        return packet

    @staticmethod
    def _send_json(connection, packet: dict) -> None:
        connection.sendall((json.dumps(packet) + "\n").encode("utf-8"))

    def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT,
                username: Optional[str] = None, password: Optional[str] = None) -> None:
        """Establish TLS, authenticate, then start receiving."""
        if not username or password is None:
            raise ValueError("A username and password are required to connect.")
        with self._state_lock:
            if self._connected:
                return

        raw_socket = socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT)
        tls_socket = None
        reader = None
        try:
            tls_socket = create_client_context().wrap_socket(raw_socket, server_hostname=host)
            tls_socket.settimeout(CONNECTION_TIMEOUT)
            reader = tls_socket.makefile("r", encoding="utf-8")

            greeting = self._read_json(reader)
            if greeting.get("type") != "auth_username":
                raise ConnectionError("Unexpected authentication response from server.")
            self._send_json(tls_socket, {"type": "username", "username": username})
            challenge = self._read_json(reader)
            if challenge.get("type") != "auth_challenge":
                raise ConnectionError("Server did not provide an authentication challenge.")
            try:
                verifier = derive_verifier(password, challenge["salt"], int(challenge["iterations"]))
                proof = hmac.new(verifier, bytes.fromhex(challenge["nonce"]), hashlib.sha256).hexdigest()
            except (KeyError, TypeError, ValueError) as error:
                raise ConnectionError("Server sent an invalid authentication challenge.") from error
            self._send_json(tls_socket, {"type": "auth_response", "proof": proof})
            result = self._read_json(reader)
            if result.get("type") != "auth_result" or result.get("ok") is not True:
                raise PermissionError("Authentication failed. Check your username and password.")
            tls_socket.settimeout(None)
            with self._state_lock:
                self._socket = tls_socket
                self._reader = reader
                self._username = username
                self._message_key = derive_message_key(verifier)
                self._send_sequence = 1
                self._receive_sequence = 1
                self._connected = True

            self._receive_thread = threading.Thread(
                target=self._receive_messages,
                name="secure-client-receiver",
                daemon=True,
            )
            self._receive_thread.start()
        except Exception:
            if reader is not None:
                try:
                    reader.close()
                except (OSError, ValueError):
                    pass
            try:
                (tls_socket or raw_socket).close()
            except OSError:
                pass
            raise

    def send_message(self, message: str) -> None:
        """Send one message protected by the session HMAC."""
        if not isinstance(message, str):
            raise TypeError("Message must be a string.")
        if not message.strip():
            raise ValueError("Message cannot be empty.")
        if "\n" in message or "\r" in message:
            raise ValueError("Messages cannot contain newline characters.")

        with self._send_lock:
            with self._state_lock:
                if not self._connected or self._socket is None or self._message_key is None:
                    raise ConnectionError("Client is not connected to the server.")
                active_socket = self._socket
                sequence = self._send_sequence
                key = self._message_key
            packet = {
                "type": "message",
                "sequence": sequence,
                "message": message,
                "mac": message_mac(key, "client-to-server", sequence, message),
            }
            try:
                self._send_json(active_socket, packet)
            except OSError:
                self.disconnect()
                raise
            with self._state_lock:
                self._send_sequence += 1

    def _receive_messages(self) -> None:
        try:
            while True:
                with self._state_lock:
                    reader = self._reader
                    key = self._message_key
                    sequence = self._receive_sequence
                if reader is None or key is None:
                    break
                line = reader.readline()
                if not line:
                    break
                packet = json.loads(line)
                if not isinstance(packet, dict):
                    raise ValueError("Server sent an invalid message packet.")
                message = packet.get("message")
                if (packet.get("type") not in {"ack", "chat", "reply"}
                        or packet.get("sequence") != sequence
                        or not isinstance(message, str)
                        or not verify_message(key, "server-to-client", sequence,
                                              message, packet.get("mac", ""))):
                    raise ValueError("Server response failed integrity verification.")
                with self._state_lock:
                    self._receive_sequence += 1
                if self.on_message is not None:
                    display = f"Server: {message}" if packet.get("type") in {"ack", "reply"} else message
                    try:
                        self.on_message(display)
                    except Exception:
                        pass
        except (OSError, ConnectionError, ValueError, TypeError):
            pass
        finally:
            self._close_connection(notify=True)

    def disconnect(self) -> None:
        self._close_connection(notify=True)

    def _close_connection(self, notify: bool) -> None:
        with self._state_lock:
            was_connected = self._connected
            self._connected = False
            active_socket, active_reader = self._socket, self._reader
            self._socket = self._reader = None
            self._username = self._message_key = None
        if active_reader is not None:
            try:
                active_reader.close()
            except (OSError, ValueError):
                pass
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                active_socket.close()
            except OSError:
                pass
        if notify and was_connected and self.on_disconnect is not None:
            try:
                self.on_disconnect()
            except Exception:
                pass
