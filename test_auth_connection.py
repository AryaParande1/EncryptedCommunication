"""Manual smoke check for an authenticated TLS connection."""

from getpass import getpass
from queue import Queue

from client.network import NetworkClient


def main() -> None:
    username = input("Username: ").strip()
    password = getpass("Password: ")
    received = Queue()
    client = NetworkClient(on_message=received.put)
    try:
        client.connect(username=username, password=password)
        client.send_message("Authenticated TLS smoke test")
        print("Server replied:", received.get(timeout=5))
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
