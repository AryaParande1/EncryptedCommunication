"""Salted password-verifier storage and challenge-response helpers."""

import hashlib
import hmac
import json
import os
import re
import secrets

from config import BASE_DIR

USERS_FILE = BASE_DIR / "security" / "users.json"
PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16
NONCE_BYTES = 32
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def derive_verifier(password: str, salt_hex: str, iterations: int) -> bytes:
    """Derive a verifier without storing or encrypting the password itself."""
    return _derive_key(password, bytes.fromhex(salt_hex), iterations)


def register_user(username: str, password: str) -> None:
    """Store a unique salt and PBKDF2 verifier for a new account."""
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3-64 characters: letters, digits, _, ., or -.")
    if len(password) < 12:
        raise ValueError("Use a password with at least 12 characters.")
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        users = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        users = {}
    if username in users:
        raise ValueError("That username already exists.")
    salt = secrets.token_bytes(SALT_BYTES)
    verifier = _derive_key(password, salt, PBKDF2_ITERATIONS)
    users[username] = {"salt": salt.hex(), "iterations": PBKDF2_ITERATIONS,
                       "verifier": verifier.hex()}
    temp_path = USERS_FILE.with_suffix(".tmp")
    temp_path.write_text(json.dumps(users, indent=2), encoding="utf-8")
    os.replace(temp_path, USERS_FILE)


def new_challenge() -> str:
    return secrets.token_hex(NONCE_BYTES)


def load_challenge_material(username: str):
    try:
        users = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        users = {}
    record = users.get(username)
    if record:
        return record["salt"], int(record["iterations"]), bytes.fromhex(record["verifier"]), True
    return secrets.token_hex(SALT_BYTES), PBKDF2_ITERATIONS, secrets.token_bytes(32), False


def verify_proof(verifier: bytes, nonce_hex: str, proof_hex: str) -> bool:
    try:
        expected = hmac.new(verifier, bytes.fromhex(nonce_hex), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, proof_hex)
    except (ValueError, TypeError):
        return False
