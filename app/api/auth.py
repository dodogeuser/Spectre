import hashlib
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import LoginSession, User, utcnow
from app.db.session import get_db
from app.security.rbac import audit

router = APIRouter(prefix="/api/auth", tags=["authentication"])
hasher = PasswordHasher()
_dummy_hash = hasher.hash(secrets.token_urlsafe(32))


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: SecretStr = Field(min_length=1, max_length=1024)


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("spectre_session", "")
    session = db.get(LoginSession, digest(token)) if token else None
    if session is None or session.expires_at <= utcnow():
        raise HTTPException(401, "Authentication required")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        supplied = request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(supplied, session.csrf_token):
            raise HTTPException(403, "Invalid CSRF token")
    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(401, "Authentication required")
    request.state.login_session = session
    return user


@router.post("/login")
def login(data: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    # JSON plus a mandatory custom header prevents cross-origin form login.
    if request.headers.get("X-Spectre-Login") != "1":
        raise HTTPException(403, "Login header required")
    if not request.app.state.login_limiter.admit(request.client.host if request.client else "unknown"):
        raise HTTPException(429, "Too many login attempts; wait one minute")
    user = db.scalar(select(User).where(User.username == data.username.strip().lower()))
    valid = False
    try:
        valid = hasher.verify(user.password_hash if user else _dummy_hash, data.password.get_secret_value())
    except (VerificationError, InvalidHashError):
        pass
    if user is None or not valid:
        audit(db, None, "auth.login_failed", "user")
        db.commit()
        raise HTTPException(401, "Invalid username or password")
    if hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(data.password.get_secret_value())
    old_token = request.cookies.get("spectre_session")
    if old_token:
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(old_token)))
    token, csrf = secrets.token_urlsafe(32), secrets.token_hex(32)
    db.add(LoginSession(token_hash=digest(token), user_id=user.id, csrf_token=csrf,
                        expires_at=utcnow() + timedelta(hours=request.app.state.settings.session_hours)))
    audit(db, user, "auth.login", "user", user.id)
    db.commit()
    response.set_cookie("spectre_session", token, httponly=True, samesite="strict",
                        secure=request.app.state.settings.secure_cookies or request.url.scheme == "https", max_age=request.app.state.settings.session_hours * 3600)
    return {"id": user.id, "username": user.username, "role": user.role, "csrf_token": csrf}


@router.get("/me")
def me(request: Request, user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role,
            "csrf_token": request.state.login_session.csrf_token}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(request.state.login_session)
    audit(db, user, "auth.logout", "user", user.id)
    db.commit()
    response.delete_cookie("spectre_session")
