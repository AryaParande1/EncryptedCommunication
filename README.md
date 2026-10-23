# Encrypted Client-Server Communication Framework

A Python desktop messaging demo using Tkinter, TLS, password authentication, message integrity checks, and optional AES-GCM encryption for user-to-user messages.

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux
- The packages listed in `requirements-tls.txt`

## Install and prepare the project

Open a regular terminal in the project folder (the prompt should not show Python's `>>>` prompt), then run:

```powershell
cd "D:\CollegeProjects\EncryptedCommunication"
python -m pip install -r requirements-tls.txt
python generate_cert.py
python create_user.py
python -m security.generate_demo_keys
```

Run `python create_user.py` once for each account you need. Usernames must be 3–64 characters and use letters, digits, `_`, `.` or `-`. Passwords must contain at least 12 characters.

The server stores a per-user salt and PBKDF2 password verifier in `security/users.json`; it does not store the original password. The certificate and private key are created under `certificates/`.

Run the demo-key generator once. It creates `security/shared_keys.json` with two AES-256 keys. Keep and copy that exact file to every client that must decrypt the demo's user-to-user messages. Do not regenerate it on one client, or the clients will have different keys.

## Start the application

Keep each process running in its own terminal, opened at the project folder.

**Terminal 1 — start the server:**

```powershell
python -m server.server
```

**Terminal 2 — start the first client:**

```powershell
python -m client.gui
```

Sign in with an account created above.

**Terminal 3 — start another client:**

```powershell
python -m client.gui
```

Sign in with a different account. In the user-to-user controls, enter the recipient's username, choose the shared AES key, and send the message. The recipient can copy the encrypted token into the decryption window and decrypt it with the matching key.

## Message modes

- **Send to Server:** Sends a message to the server, which returns a simple configured response. The optional Caesar setting is a classroom demonstration only; Caesar cipher is not secure.
- **Send to User:** Encrypts a message using AES-GCM and the selected shared key. The server relays the encrypted token to the recipient. The recipient decrypts it using the same key.
- **TLS and integrity:** TLS protects the client-server connection. Sequence numbers and HMAC checks help detect altered or replayed packets.

AES-GCM message encryption is separate from TLS: TLS protects the connection to the server, while AES-GCM protects the user-to-user message content in the relayed token.

## Project layout

```text
EncryptedCommunication/
├── client/
│   ├── gui.py                 # Tkinter login and chat window
│   └── network.py             # TLS client, authentication, and packet handling
├── server/
│   ├── responses.py           # Server response rules
│   └── server.py              # TLS server, authentication, integrity, and routing
├── security/
│   ├── auth.py                # PBKDF2 verifier storage and challenge-response helpers
│   ├── integrity.py           # HMAC and message-key helpers
│   ├── message_encryption.py  # AES-GCM encrypt/decrypt helpers
│   ├── tls_manager.py         # TLS context setup
│   ├── generate_demo_keys.py  # One-time demo key creation
│   ├── users.json             # Account salts and password verifiers
│   └── shared_keys.json       # Shared demo AES keys
├── certificates/              # Generated TLS certificate and private key
├── logs/                      # Runtime application log
├── config.py                  # Host, port, paths, and UI settings
├── create_user.py             # Interactive account creation
└── generate_cert.py           # TLS certificate generation
```

## Troubleshooting

- If `python` opens the Python prompt (`>>>`), type `exit()` before running terminal commands.
- If login fails, confirm that the account exists in the server project's `security/users.json` and use the password created for that account.
- If the server cannot start, check that `certificates/server.crt` and `certificates/server.key` exist; run `python generate_cert.py` if they do not.
- If encrypted user messages cannot be decrypted, confirm both clients have the same `security/shared_keys.json` and that the same key name is selected.
- By default, `config.py` uses `127.0.0.1`, so the server and clients are expected to run on the same computer. Connecting from other computers requires configuring the server address and TLS certificate appropriately.

## Learning-project security note

This is a learning demo, not a production messaging system. The AES keys are shared through a file, the server uses a locally generated TLS certificate, and the Caesar option is not secure. Do not use it to protect sensitive real-world communications.
