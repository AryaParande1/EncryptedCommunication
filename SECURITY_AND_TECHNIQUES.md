Security and Technical Methods Used

This guide explains the security methods and supporting technologies in the Encrypted Client-Server Communication Framework. It distinguishes encryption from authentication, integrity checking, encoding, and demonstration techniques.

## Security methods

### 1. TLS (Transport Layer Security)

**Purpose:** Protects the network connection between a client and the server.

**How this project uses it:** The client and server create TLS sockets using Python's `ssl` module. The server loads `certificates/server.crt` and `certificates/server.key`. The client checks the server certificate before sending login or chat data.

**What it protects:** Information traveling between that client and server, including login protocol messages and chat packets, is encrypted while in transit. TLS also checks that the client is talking to a server with the expected certificate.

**Where it appears:** `security/tls_manager.py`, `generate_cert.py`, `client/network.py`, and `server/server.py`.

**Project limitation:** The included certificate is self-signed for development. Clients need to trust the matching certificate. The default address `127.0.0.1` is for clients on the same computer. A real deployment would require carefully configured certificates and network settings.

### 2. Password-based key derivation with PBKDF2-HMAC-SHA-256

**Purpose:** Avoid storing the user's actual password. PBKDF2 applies a salted, repeated derivation to make password guessing more expensive.

**How this project uses it:** At account creation, the program generates a random 16-byte salt and derives a verifier from the password using PBKDF2-HMAC-SHA-256 with 310,000 iterations. `security/users.json` stores the salt, iteration count, and verifier. The original password is not stored, encrypted or otherwise.

**Where it appears:** `security/auth.py` and `create_user.py`.

### 3. Challenge-response login

**Purpose:** Let the server check that a client knows the password without sending the password itself as the login proof.

**How this project uses it:** The client sends its username over TLS. The server returns that account's salt and iteration count plus a fresh random challenge. The client derives the password verifier and computes an HMAC proof over the challenge. The server checks the proof against its stored verifier and accepts or rejects the login.

**Where it appears:** The server's `authenticate()` function in `server/server.py`; the client handshake in `client/network.py`; helper functions in `security/auth.py`.

### 4. HMAC-SHA-256 message integrity checks

**Purpose:** Detect whether a protected message packet has been changed and confirm it was created by a party with the session key.

**How this project uses it:** After authentication, the client and server derive a separate message-integrity key from the password verifier. Each message packet carries an HMAC over its direction, sequence number, and message text. The receiving side recomputes the HMAC and compares it before processing the packet.

**Where it appears:** `security/integrity.py`, `client/network.py`, and `server/server.py`.

**Important distinction:** HMAC does not encrypt or hide the message. TLS encrypts the client-server connection; HMAC detects changes to the packet.

### 5. Sequence numbers

**Purpose:** Keep packets in order and reject a packet with an unexpected sequence number on the current connection.

**How this project uses it:** Client-to-server and server-to-client packets have separate increasing counters. The sequence number is included in the HMAC, so changing it also invalidates the HMAC.

**Where it appears:** `client/network.py`, `server/server.py`, and `security/integrity.py`.

### 6. AES-256-GCM user-to-user message encryption

**Purpose:** Encrypt the content of a user-to-user message and authenticate it so the recipient can detect an incorrect key or modified token.

**How this project uses it:** `security/message_encryption.py` loads one of two 32-byte shared demo keys from `security/shared_keys.json`. For each message it creates a new 12-byte random nonce and encrypts the text using AES-GCM. The key name is also supplied as associated data, so it is authenticated but not encrypted. The code packages the nonce and AES-GCM output (ciphertext plus authentication tag) into an `ENC2` token.

The server relays the token to the recipient but does not decrypt its AES-GCM contents. The recipient uses the same key file and selected key to decrypt the token in the GUI.

**Where it appears:** `security/message_encryption.py`, `security/generate_demo_keys.py`, `client/gui.py`, and `server/server.py` for forwarding.

**Project limitation:** The demo keys are shared through a file. Anyone who obtains that file can decrypt messages made with those keys. This project does not implement secure key exchange or per-user key management.

### 7. Caesar cipher demonstration

**Purpose:** Demonstrate a simple letter substitution for server-directed messages.

**How this project uses it:** When selected, letters are shifted by a fixed amount before the client sends the server-directed message; the server reverses the shift to process it and can shift the response back.

**Security status:** A Caesar cipher is not secure encryption. It can be broken easily and must not be used to protect private information. It is included only as a basic educational demonstration.

**Where it appears:** Inline helper functions in `client/gui.py` and `server/server.py`. A separate helper also exists in `security/caesar_cipher.py`.

## Supporting technologies and formats

### TCP sockets

TCP provides a reliable, ordered byte stream between each client and the server. TLS is layered on top of the TCP socket. The server accepts multiple client connections and starts a handler thread for each one.

**Where it appears:** `client/network.py` and `server/server.py`.

### JSON packets

JSON is used to represent protocol packets such as authentication challenges and messages. A newline marks the end of each JSON packet when it travels over the socket. JSON is a data format; it does not itself provide encryption or security.

**Where it appears:** `client/network.py`, `server/server.py`, `security/auth.py`, and `security/message_encryption.py`.

### Base64 encoding

Base64 converts the AES nonce and encrypted binary data into printable text so the token can be carried in JSON and copied into the decrypt window. Base64 is encoding, not encryption; anyone can decode it, but the decoded ciphertext still requires the AES key to read.

**Where it appears:** `security/message_encryption.py` and `security/generate_demo_keys.py`.

### Random values and nonces

The project uses Python's `secrets` module for salts, challenges, and shared demo keys, and `os.urandom()` for each AES-GCM nonce. A salt is unique per account; a challenge is fresh for a login attempt; the AES-GCM nonce must be fresh for every encryption with a given key.

**Where it appears:** `security/auth.py`, `security/generate_demo_keys.py`, and `security/message_encryption.py`.

### Tkinter and threads

Tkinter provides the desktop login, chat window, send controls, and decrypt interface. The client uses a background thread for network receiving so incoming messages do not freeze the interface. The server uses a thread per client connection.

**Where it appears:** `client/gui.py`, `client/network.py`, and `server/server.py`.

## How the protections fit together

```text
User enters password
        ↓
PBKDF2 verifier + challenge-response authenticate the user
        ↓
TLS encrypts the client ↔ server connection
        ↓
HMAC + sequence numbers protect packet integrity and order
        ↓
For user-to-user content, AES-GCM encrypts the message before relay
        ↓
Recipient decrypts the token using the shared AES key
```

For a message to the server, TLS protects it in transit, while the server receives and processes its content. For a user-to-user message, AES-GCM protects the message content in the token as the server forwards it.

## What is and is not encryption in this project

| Method | Encrypts data? | Main role here |
|---|---:|---|
| TLS | Yes | Protects the client-server connection |
| AES-GCM | Yes | Protects user-to-user message content |
| PBKDF2 | No | Derives a stored password verifier |
| Challenge-response HMAC | No | Proves password knowledge during login |
| Message HMAC | No | Detects packet changes |
| Sequence number | No | Checks packet order on a connection |
| Base64 | No | Encodes binary data as printable text |
| Caesar cipher | Not securely | Simple educational shift demonstration |

## Main source files by technique

- `security/auth.py` — PBKDF2 password verifiers and challenge-response helpers.
- `security/integrity.py` — message HMAC and sequence-integrity helpers.
- `security/message_encryption.py` — AES-GCM encryption and decryption.
- `security/tls_manager.py` — TLS client and server contexts.
- `security/generate_demo_keys.py` — creates the shared AES demo keys.
- `generate_cert.py` — creates the local development TLS certificate and private key.
- `client/network.py` — client TLS connection, authentication, and protected packet exchange.
- `client/gui.py` — sign-in, chat controls, Caesar demo, and decrypt window.
- `server/server.py` — TLS listener, authentication, integrity checks, server responses, and encrypted-token relay.