Project File Guide: What Happens, in Order

This guide follows the project from first-time setup to sending and receiving a message. Paths are relative to the `EncryptedCommunication` project folder.

## 1. First-time setup

### `requirements-tls.txt`

Lists the Python packages needed by the project, including the cryptography package used for certificates and AES-GCM. Install these packages before starting the application:

```powershell
python -m pip install -r requirements-tls.txt
```

### `config.py`

Central settings used by other modules: server address and port, certificate paths, log path, and interface defaults. `BASE_DIR` points to the project folder. The default server address is `127.0.0.1`, which is for clients running on the same computer as the server.

### `generate_cert.py` and `certificates/`

`generate_cert.py` creates a development TLS certificate and private key. The files are written to `certificates/server.crt` and `certificates/server.key`. The server loads them when it starts; clients use the certificate to verify the TLS connection.

Run once, or again if the certificate files are missing:

```powershell
python generate_cert.py
```

Keep `server.key` private. Do not share it with clients; clients need the certificate file, not the server's private key.

### `create_user.py`, `security/auth.py`, and `security/users.json`

`create_user.py` asks for a username and password, then calls `register_user()` in `security/auth.py`. That module creates a unique random salt and derives a PBKDF2 password verifier. The JSON record stores the salt, iteration count, and verifier; it does not store the original password.

The account file is created at `security/users.json` when the first account is registered. Create one account for each person who should sign in:

```powershell
python create_user.py
```

### `security/generate_demo_keys.py` and `security/shared_keys.json`

This generator creates two random 32-byte AES keys, named `key1` and `key2`, and saves them in `security/shared_keys.json`:

```powershell
python -m security.generate_demo_keys
```

Run it once. Copy the same `shared_keys.json` to every client that needs to decrypt messages. If different clients have different key files, they cannot decrypt each other's messages.

## 2. Starting the server

### `security/tls_manager.py`

Creates TLS contexts. The server context loads its certificate and private key. The client context verifies the server certificate.

### `security/integrity.py`

Derives a message-integrity key and creates or verifies HMACs. HMACs and sequence numbers help the receiver detect modified, misordered, or replayed packets.

### `server/responses.py`

Contains the server's preset response rules for messages sent to the server.

### `server/server.py`

The server entry point. It opens the listening socket, accepts clients, wraps each connection in TLS, authenticates the client, verifies message HMACs and sequence numbers, and routes messages. It sends server-directed messages to the response rules and relays encrypted user-message tokens to connected recipients.

Start it in the first terminal and leave it running:

```powershell
python -m server.server
```

## 3. Signing in from a client

### `client/gui.py`

Starts the Tkinter desktop application. It displays the username/password sign-in form, then the chat controls after successful login. It also handles separate send-to-server and send-to-user actions and provides a window for decrypting a received token.

### `client/network.py`

Manages the client's network connection. It opens TLS, follows the authentication challenge exchange, derives the password verifier from the entered password using `security/auth.py`, and sends/receives integrity-protected packets using `security/integrity.py`.

### Authentication sequence

1. The client sends the username over the TLS connection.
2. The server looks up that user's salt and PBKDF2 verifier in `security/users.json` and sends the salt, iteration count, and a fresh random challenge.
3. The client derives a verifier from the entered password and creates a proof for the challenge.
4. The server checks the proof against the stored verifier and accepts or rejects the login.
5. On success, client and server derive message-integrity keys for the connection.

Launch a client in a second terminal:

```powershell
python -m client.gui
```

Launch another client in a third terminal and sign in as a different user to try user-to-user messaging.

## 4. Sending a message to the server

1. The user enters text in `client/gui.py` and selects **Send to Server**.
2. The GUI optionally applies the Caesar demonstration transform, then asks `client/network.py` to send the message.
3. `client/network.py` adds a sequence number and HMAC and sends the packet over TLS.
4. `server/server.py` verifies the sequence and HMAC, then passes the text to `server/responses.py`.
5. The server sends its response back over TLS with a sequence number and HMAC; the client verifies it and displays it.

The Caesar option is a classroom cipher demonstration, not real encryption. TLS protects the client-server connection.

## 5. Sending an encrypted message to another user

### `security/message_encryption.py`

Loads `key1` or `key2` from `security/shared_keys.json` and uses the Python cryptography library's AES-GCM implementation. For each message, it creates a fresh 12-byte nonce. AES-GCM returns encrypted bytes and an authentication tag; the module packages the nonce and result into a Base64 token beginning with `ENC2:` and the key name.

The flow is:

1. The sender enters the recipient's username and chooses a shared AES key in `client/gui.py`.
2. `security/message_encryption.py` encrypts the message and returns an `ENC2` token.
3. `client/network.py` sends the token inside the TLS and HMAC-protected client-server packet.
4. `server/server.py` checks the packet and forwards the token to the recipient who is online. The server relays the encrypted token; it does not decrypt the AES-GCM message.
5. The recipient copies the token into the decrypt window in `client/gui.py`.
6. `security/message_encryption.py` uses the matching key from the recipient's shared key file to decrypt and authenticate the token, then displays the original text.

## 6. Optional command-line connection check

### `test_auth_connection.py`

Prompts for an account, connects through TLS, authenticates, sends a smoke-test message, and prints the server response. Run it while the server is running:

```powershell
python test_auth_connection.py
```

### `test_connection.py`

Small wrapper that starts the same authenticated connection check:

```powershell
python test_connection.py
```

## 7. Other files and folders

- `security/caesar_cipher.py`: Caesar cipher helper. The current GUI/server demonstration also has Caesar functions inline, so this separate helper may not be used by the active GUI path.
- `TLS_SETUP.md`: additional notes on generating and configuring TLS certificates.
- `INTEGRITY_SETUP.md`: additional notes on HMAC integrity checks.
- `README.md`: quick project overview and setup/run instructions.
- `logs/application.log`: runtime server log, created or appended to when the server runs.
- `__pycache__/`: Python-generated bytecode cache; not source code and normally not edited by hand.

## Complete runtime order at a glance

```text
config.py and requirements
        ↓
generate_cert.py → certificates/server.crt + server.key
        ↓
create_user.py → security/users.json
        ↓
security/generate_demo_keys.py → security/shared_keys.json
        ↓
server.server → TLS listener and authentication/routing
        ↓
client.gui → client.network → TLS sign-in
        ↓
server message response OR AES-GCM user-message relay and decryption