"""Explicit operator-controlled administrator provisioning."""
import argparse

from app.database.connection import transaction, init_db


def provision(email: str) -> None:
    init_db()
    with transaction() as connection:
        updated = connection.execute(
            "UPDATE users SET role='admin', email_verified=TRUE WHERE lower(email)=lower(?)",
            (email.strip(),),
        )
        if updated.rowcount != 1:
            raise SystemExit("No existing account matched the requested administrator email")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    provision(parser.parse_args().email)
