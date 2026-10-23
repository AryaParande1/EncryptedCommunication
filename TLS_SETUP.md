# TLS and password login setup

Passwords are not saved in plaintext and are not encrypted for later recovery.
The server stores a per-user random salt and a PBKDF2-HMAC-SHA256 verifier in
`security/users.json`, then checks a fresh challenge response at sign-in.

## Prepare the certificate and dependency

From the project root:

```text
python -m pip install -r requirements.txt
python generate_certificate.py
```

The client trusts the local certificate. Keep `SERVER_HOST` in `config.py`
consistent with the address used by the client.

## Create an account

Run once for each user:

```text
python create_user.py
```

Choose a username and password of at least 12 characters. The entered password
is used to derive a verifier; only the salt, iteration count and verifier are
stored. Keep `security/users.json` on the server and out of public source control.

## Start the server and client

Terminal 1, from the project root:

```text
python -m server.server
```

Terminal 2, from the same project root:

```text
python -m client.gui
```

Sign in with the account created above. For user-to-user AES-GCM messaging,
generate the demo keys once and copy the same `security/shared_keys.json` to both
clients:

```text
python -m security.generate_demo_keys
```

The shared demo-key file is separate from password storage and is not suitable
for production key management.
