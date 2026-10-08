"""Run as python -m scripts.create_user; passwords are entered privately."""
import argparse
from getpass import getpass

from sqlalchemy import select

from app.api.auth import hasher
from app.config import get_settings
from app.db.models import User
from app.db.session import make_session_factory
from app.security.rbac import audit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("--role", choices=["admin", "investigator", "viewer"], default="investigator")
    args = parser.parse_args()
    username = args.username.strip().lower()
    if not username or len(username) > 100:
        parser.error("Username must contain 1–100 characters")
    password = getpass("Password (minimum 12 characters): ")
    if len(password) < 12 or len(password) > 1024 or password != getpass("Confirm password: "):
        parser.error("Passwords must match and contain 12–1024 characters")
    with make_session_factory(get_settings())() as db:
        if db.scalar(select(User).where(User.username == username)):
            parser.error("Username already exists")
        user = User(username=username, role=args.role, password_hash=hasher.hash(password))
        db.add(user)
        db.flush()
        audit(db, None, "user.provision_local", "user", user.id, role=args.role)
        db.commit()
    print("Local account created.")


if __name__ == "__main__":
    main()
