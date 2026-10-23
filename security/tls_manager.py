"""Create TLS contexts for the communication server and client."""

import ssl

from config import TLS_CERT_FILE, TLS_KEY_FILE


def create_server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(TLS_CERT_FILE), keyfile=str(TLS_KEY_FILE))
    return context


def create_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(TLS_CERT_FILE))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context
