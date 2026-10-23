from pathlib import Path

PROJECT_NAME = "Encrypted Client-Server Communication Framework"
BASE_DIR = Path(__file__).resolve().parent

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
MAX_CLIENTS = 5
SOCKET_BUFFER_SIZE = 4096
CONNECTION_TIMEOUT = 10

CERT_DIR = BASE_DIR / "certificates"
TLS_CERT_FILE = CERT_DIR / "server.crt"
TLS_KEY_FILE = CERT_DIR / "server.key"

LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "application.log"

APP_TITLE = "Secure Communication Client"
APP_WIDTH = 600
APP_HEIGHT = 480


def initialize_directories():
    """Create required runtime directories if missing."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    initialize_directories()
    print(f"Project directory : {BASE_DIR}")
    print(f"Server address    : {SERVER_HOST}:{SERVER_PORT}")
    print(f"TLS certificate   : {TLS_CERT_FILE}")
    print(f"TLS private key   : {TLS_KEY_FILE}")
