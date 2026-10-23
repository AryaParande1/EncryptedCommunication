"""Interactively add an account with a salted PBKDF2 password verifier."""

from getpass import getpass

from security.auth import register_user


def main() -> None:
    username = input("New username: ").strip()
    password = getpass("New password (12+ characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match; no account was created.")
    try:
        register_user(username, password)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"Created account for {username!r}.")


if __name__ == "__main__":
    main()
