from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from jwt.exceptions import PyJWTError as JWTError
import bcrypt
from fastapi.security import OAuth2PasswordBearer
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# bcrypt work factor. 10 is the OWASP minimum and about 4x faster than the library
# default of 12, which took ~1.7 s per check on the small hosting CPU. Older hashes keep
# working (the factor is stored in each hash) and are upgraded at the next sign-in.
PASSWORD_HASH_ROUNDS = 10


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(PASSWORD_HASH_ROUNDS)).decode('utf-8')


def password_needs_rehash(hashed_password: str) -> bool:
    """True when a stored hash uses a different work factor than PASSWORD_HASH_ROUNDS."""
    try:
        return int(hashed_password.split("$")[2]) != PASSWORD_HASH_ROUNDS
    except (AttributeError, IndexError, ValueError):
        return False


# bcrypt is CPU-bound. Called directly inside an async endpoint it blocks the event loop,
# so every other request waits while one person signs in. These run it in a worker thread.
async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def get_password_hash_async(password: str) -> str:
    return await asyncio.to_thread(get_password_hash, password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

from cryptography.fernet import Fernet, InvalidToken

_fernet = Fernet(settings.GITHUB_TOKEN_ENCRYPTION_KEY.encode())

def encrypt_token(plain_token: str) -> str:
    if not plain_token:
        return plain_token
    return _fernet.encrypt(plain_token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    if not encrypted_token:
        return encrypted_token
    # check if it looks encrypted (could be plain if old data)
    if not encrypted_token.startswith("gAAAAA"):
        return encrypted_token
    try:
        return _fernet.decrypt(encrypted_token.encode()).decode()
    except InvalidToken:
        return ""  # Invalid or corrupted token, requires re-auth
