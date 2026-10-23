"""Message-level HMAC integrity and sequence-number helpers."""

import hashlib
import hmac


def derive_message_key(password_verifier: bytes) -> bytes:
    """Derive a separate message MAC key from the password verifier."""
    return hmac.new(password_verifier, b"ECF message integrity v1", hashlib.sha256).digest()


def message_mac(key: bytes, direction: str, sequence: int, message: str) -> str:
    if direction not in {"client-to-server", "server-to-client"}:
        raise ValueError("Unsupported message direction.")
    if sequence < 1:
        raise ValueError("Sequence numbers start at 1.")
    data = f"ECF1\n{direction}\n{sequence}\n{message}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_message(key: bytes, direction: str, sequence: int, message: str, supplied_mac: str) -> bool:
    try:
        expected = message_mac(key, direction, sequence, message)
        return hmac.compare_digest(expected, supplied_mac)
    except (TypeError, ValueError):
        return False
