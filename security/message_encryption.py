"""AES-GCM message encryption using the shared demo key file."""

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import BASE_DIR

SHARED_KEYS_FILE = BASE_DIR / "security" / "shared_keys.json"
NONCE_SIZE = 12
KEY_SIZE = 32


def load_shared_keys() -> dict[str, bytes]:
    """Load and validate key1/key2 from security/shared_keys.json."""
    try:
        records = json.loads(SHARED_KEYS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(
            "Shared keys are missing. Run the demo-key generator first."
        ) from error
    if not isinstance(records, dict):
        raise ValueError("The shared key file must contain a JSON object.")

    keys = {}
    for key_id in ("key1", "key2"):
        encoded = records.get(key_id)
        if not isinstance(encoded, str):
            raise ValueError(f"The shared key file is missing {key_id}.")
        try:
            key = base64.b64decode(encoded, validate=True)
        except Exception as error:
            raise ValueError(f"{key_id} is not valid base64.") from error
        if len(key) != KEY_SIZE:
            raise ValueError(f"{key_id} must decode to a 32-byte AES-256 key.")
        keys[key_id] = key
    return keys


def encrypt_with_shared_key(plaintext: str, key_id: str) -> str:
    """Encrypt a message and return an ENC2 token containing its key ID."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Message cannot be empty.")
    keys = load_shared_keys()
    if key_id not in keys:
        raise ValueError("Choose key1 or key2.")

    nonce = os.urandom(NONCE_SIZE)
    encrypted = AESGCM(keys[key_id]).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        key_id.encode("ascii"),
    )
    token_data = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")
    return f"ENC2:{key_id}:{token_data}"


def decrypt_with_shared_key(token: str) -> str:
    """Decrypt an ENC2 token using its key ID and the local shared key file."""
    if not isinstance(token, str):
        raise ValueError("Encrypted message must be text.")
    parts = token.strip().split(":", 2)
    if len(parts) != 3 or parts[0] != "ENC2" or parts[1] not in {"key1", "key2"}:
        raise ValueError("Expected an ENC2:key1:... or ENC2:key2:... message.")

    key_id, encoded = parts[1], parts[2]
    try:
        payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except Exception as error:
        raise ValueError("Encrypted message text is invalid or incomplete.") from error
    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Encrypted message is incomplete.")

    nonce, encrypted = payload[:NONCE_SIZE], payload[NONCE_SIZE:]
    try:
        plaintext = AESGCM(load_shared_keys()[key_id]).decrypt(
            nonce,
            encrypted,
            key_id.encode("ascii"),
        )
        return plaintext.decode("utf-8")
    except Exception as error:
        raise ValueError(
            "Decryption failed. Check that the same shared key file is installed."
        ) from error
