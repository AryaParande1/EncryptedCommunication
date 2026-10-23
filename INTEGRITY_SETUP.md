# Message integrity

After the client proves its password during the TLS sign-in challenge, the
client and server derive an application message key from the password verifier.
Each packet includes a direction-specific HMAC-SHA256 and sequence number. The
receiving side verifies both before accepting the message.

This project also uses TLS, which protects the connection in transit. The
application HMAC is kept as a separate integrity-checking demonstration.

Create an account with `python create_user.py`, then start the server and GUI as
described in `TLS_SETUP.md`.
