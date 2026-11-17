import hashlib
import logging
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select, or_, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import throttle
from app.auth.deps import get_current_user, invalidate_user_cache
from app.auth.security import get_password_hash, verify_password, create_access_token, encrypt_token
from app.config import settings, is_production
from app.database.models import User
from app.database.session import get_db
from app.schemas.user import UserCreate, UserResponse
from app.utils.mailer import send_email, smtp_configured

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
oauth_states: dict[str, float] = {}

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
GITHUB_USERNAME_SUFFIX = "-github"
INVALID_CREDENTIALS = "Incorrect username/email or password."
RESET_REQUEST_ACK = "If an account exists for that email, a password reset link has been sent."


class ForgotPasswordRequest(BaseModel):
    email: str


class PasswordResetRequest(BaseModel):
    token: str
    new_password: str


def validate_password_strength(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    return password


def _password_fingerprint(hashed_password: str) -> str:
    """Binds a reset token to the current password so it stops working once used."""
    return hashlib.sha256((hashed_password or "").encode("utf-8")).hexdigest()[:24]


def create_password_reset_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "type": "password_reset",
        "pwd": _password_fingerprint(user.hashed_password),
        "iat": now,
        "exp": now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _issue_access_token(user: User) -> str:
    role = getattr(user, "role", None) or "Analyst"
    return create_access_token(
        data={"sub": str(user.username), "role": role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    email_clean = user.email.strip().lower()
    username_clean = user.username.strip()

    if not USERNAME_PATTERN.match(username_clean) or username_clean.lower().endswith(GITHUB_USERNAME_SUFFIX):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 characters using letters, numbers, dot, dash or underscore.",
        )
    validate_password_strength(user.password)

    existing = (await db.execute(
        select(User).where(
            or_(
                func.lower(User.email) == email_clean,
                func.lower(User.username) == username_clean.lower(),
            )
        )
    )).scalars().first()
    if existing:
        if (existing.email or "").lower() == email_clean:
            raise HTTPException(status_code=400, detail="Email already registered. Please sign in.")
        raise HTTPException(status_code=400, detail="Username is already taken. Please choose another.")

    db_user = User(
        username=username_clean,
        email=email_clean,
        hashed_password=get_password_hash(user.password),
        is_active=True,
    )
    db.add(db_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Username or email is already registered.")
    await db.refresh(db_user)
    return db_user


@router.post("/login")
async def login(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    login_id = ""
    password = ""

    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
            login_id = str(body.get("username") or body.get("email") or "").strip()
            password = str(body.get("password") or "")
        except Exception:
            pass

    if not login_id or not password:
        try:
            form = await request.form()
            login_id = str(form.get("username") or form.get("email") or "").strip()
            password = str(form.get("password") or "")
        except Exception:
            pass

    if not login_id or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username/email and password are required.",
        )

    throttle.ensure_not_locked(login_id)

    user = (await db.execute(
        select(User).where(
            or_(
                func.lower(User.username) == login_id.lower(),
                func.lower(User.email) == login_id.lower()
            )
        )
    )).scalars().first()

    # Unknown accounts and wrong passwords get the same answer; nothing is created here.
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        throttle.record_failure(login_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    throttle.clear(login_id)
    uname = str(user.username)
    uemail = str(user.email)
    user_role = getattr(user, "role", None) or "Analyst"

    try:
        user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
    except Exception:
        await db.rollback()

    access_token = create_access_token(
        data={"sub": uname, "role": user_role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer", "username": uname, "email": uemail, "role": user_role}


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Starts a password reset. Always answers the same way so accounts cannot be enumerated."""
    email_clean = req.email.strip().lower()
    if not email_clean or len(email_clean) > 320:
        return {"message": RESET_REQUEST_ACK}

    throttle.ensure_not_locked(f"reset:{email_clean}")
    throttle.record_failure(f"reset:{email_clean}")  # also caps how many mails one address can trigger

    user = (await db.execute(select(User).where(func.lower(User.email) == email_clean))).scalars().first()
    if user and user.is_active:
        token = create_password_reset_token(user)
        base_url = settings.FRONTEND_URL.split(",")[0].strip().rstrip("/")
        link = f"{base_url}/reset-password?token={quote(token)}"
        if smtp_configured():
            await send_email(
                user.email,
                "Reset your ZyloRun password",
                "A password reset was requested for your ZyloRun account.\n\n"
                f"Open this link within {settings.PASSWORD_RESET_TOKEN_MINUTES} minutes to choose a new password:\n{link}\n\n"
                "If you did not request this, you can ignore this email.",
            )
        elif not is_production(settings):
            # Local development convenience only; never printed in production.
            logger.warning("SMTP is not configured. Development password reset link: %s", link)
        else:
            logger.error("Password reset requested but SMTP is not configured; no email was sent.")
    return {"message": RESET_REQUEST_ACK}


@router.post("/reset-password")
async def reset_password(req: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    """Completes a reset. Requires the single-use token that was e-mailed to the account owner."""
    invalid = HTTPException(status_code=400, detail="This password reset link is invalid or has expired.")
    try:
        payload = jwt.decode(req.token.strip(), settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "password_reset":
            raise invalid
        user_id = int(payload.get("sub"))
    except HTTPException:
        raise
    except Exception:
        raise invalid

    new_password = validate_password_strength(req.new_password)

    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if not user or not user.is_active or payload.get("pwd") != _password_fingerprint(user.hashed_password):
        raise invalid

    user.hashed_password = get_password_hash(new_password)
    await db.commit()
    invalidate_user_cache(user.username)
    throttle.clear(user.email)
    throttle.clear(user.username)
    return {"message": "Password updated. You can now sign in."}


class DeleteAccountRequest(BaseModel):
    password: str = ""
    confirm: str = ""


@router.delete("/me")
async def delete_my_account(
    req: DeleteAccountRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently deletes the caller's account together with their repositories,
    scans, findings, targets and run history (removed by cascade)."""
    if req.confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Type DELETE in the confirm field to delete your account.")

    user = (await db.execute(select(User).where(User.id == current_user.id))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    if user.hashed_password and not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=403, detail="Password is incorrect.")
    if user.role == "Admin":
        other_admins = (await db.execute(
            select(func.count()).select_from(User).where(User.role == "Admin", User.id != user.id, User.is_active.is_(True))
        )).scalar() or 0
        if other_admins == 0:
            raise HTTPException(status_code=400, detail="The last administrator account cannot be deleted.")

    username = user.username
    await db.delete(user)
    await db.commit()
    invalidate_user_cache(username)
    return {"message": "Your account and its data have been deleted."}


@router.get("/github/login")
async def github_login():
    now = time.time()
    for stale in [s for s, expires in list(oauth_states.items()) if expires < now]:
        oauth_states.pop(stale, None)
    state = secrets.token_urlsafe(32)
    oauth_states[state] = now + settings.GITHUB_OAUTH_STATE_TTL_SECONDS
    response = RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&scope=repo%20user&state={state}")
    response.set_cookie("github_oauth_state", state, httponly=True, samesite="none", secure=settings.FRONTEND_URL.startswith("https"), max_age=settings.GITHUB_OAUTH_STATE_TTL_SECONDS)
    return response


async def _find_or_create_github_user(db: AsyncSession, login: str, email: str, encrypted_token: str) -> User:
    """Accounts created through GitHub have no local password. A password account that
    happens to share the GitHub login is never handed over to the GitHub user."""
    candidates = (login, f"{login}{GITHUB_USERNAME_SUFFIX}")
    for candidate in candidates:
        existing = (await db.execute(select(User).where(func.lower(User.username) == candidate.lower()))).scalars().first()
        if existing and not existing.hashed_password:
            existing.github_access_token = encrypted_token
            return existing

    username = login
    taken = (await db.execute(select(User).where(func.lower(User.username) == login.lower()))).scalars().first()
    if taken:
        username = f"{login}{GITHUB_USERNAME_SUFFIX}"
    email_taken = (await db.execute(select(User).where(func.lower(User.email) == email.lower()))).scalars().first()
    if email_taken:
        email = f"{login}@users.noreply.github.com"
    user = User(username=username, email=email, hashed_password="", github_access_token=encrypted_token)
    db.add(user)
    return user


@router.get("/github/callback")
async def github_callback(code: str, state: str, request: Request, db: AsyncSession = Depends(get_db)):
    expires_at = oauth_states.pop(state, 0)
    if not secrets.compare_digest(state, request.cookies.get("github_oauth_state", "")) or expires_at < time.time():
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Exchange code for access token
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code
                }
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")

            if not access_token:
                raise HTTPException(status_code=400, detail="Could not authenticate with GitHub")

            # Get user info
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            user_response.raise_for_status()
            github_user = user_response.json()

        login = github_user.get("login")
        if not login:
            raise HTTPException(status_code=400, detail="Could not authenticate with GitHub")
        email = (github_user.get("email") or f"{login}@users.noreply.github.com").lower()

        user = await _find_or_create_github_user(db, login, email, encrypt_token(access_token))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="This GitHub account could not be linked. Please contact support.")
        await db.refresh(user)

        frontend_base = settings.FRONTEND_URL.split(",")[0].strip().rstrip("/")
        response = RedirectResponse(f"{frontend_base}/dashboard#token={_issue_access_token(user)}")
        response.delete_cookie("github_oauth_state")
        return response
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="GitHub authentication is unavailable")
