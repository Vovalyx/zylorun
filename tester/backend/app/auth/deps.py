from fastapi import Depends, HTTPException, Request, status
import jwt
from jwt.exceptions import PyJWTError as JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.models import User, RoleEnum
from app.database.session import get_db

import time
from typing import Dict, Tuple

_USER_CACHE: Dict[str, Tuple[User, float]] = {}
_CACHE_TTL = 60.0  # 60 seconds cache lifetime

def invalidate_user_cache(username: str | None = None):
    global _USER_CACHE
    if username:
        _USER_CACHE.pop(username, None)
    else:
        _USER_CACHE.clear()

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    authorization = request.headers.get("authorization", "")
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    if not token:
        # Check query params (for WebSockets)
        token = request.query_params.get("token", "")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        if not username or payload.get("type") != "access":
            raise JWTError("invalid access token")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    now = time.time()
    cached = _USER_CACHE.get(username)
    if cached and cached[1] > now:
        return cached[0]

    result = await db.execute(select(User).where(User.username == username, User.is_active.is_(True)))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Clean old cache entries if cache size grows large
    if len(_USER_CACHE) > 5000:
        expired_keys = [k for k, (_, exp) in _USER_CACHE.items() if exp <= now]
        for k in expired_keys:
            _USER_CACHE.pop(k, None)

    _USER_CACHE[username] = (user, now + _CACHE_TTL)
    return user

def require_role(allowed_roles: list[str]):
    async def role_checker(current_user: User = Depends(get_current_user)):
        user_role = getattr(current_user, "role", "Analyst")
        if user_role not in allowed_roles and user_role != "Admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {allowed_roles}"
            )
        return current_user
    return role_checker
