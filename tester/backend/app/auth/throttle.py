"""In-memory failed-login throttle keyed by account identifier.

Unlike an IP-based limit this cannot be bypassed by spoofing a forwarding
header: after too many failures the *account* is locked for a short window.
State is per-process; for multiple workers move it to a shared store.
"""
import time
from typing import Dict, List

from fastapi import HTTPException, status

MAX_FAILURES = 10
WINDOW_SECONDS = 15 * 60
_MAX_TRACKED_KEYS = 20000

_failures: Dict[str, List[float]] = {}


def _normalise(key: str) -> str:
    return (key or "").strip().lower()[:320]


def _recent(key: str, now: float) -> List[float]:
    stamps = [t for t in _failures.get(key, []) if t > now - WINDOW_SECONDS]
    if stamps:
        _failures[key] = stamps
    else:
        _failures.pop(key, None)
    return stamps


def ensure_not_locked(key: str) -> None:
    """Raise 429 when the identifier has too many recent failed attempts."""
    key = _normalise(key)
    if not key:
        return
    now = time.time()
    stamps = _recent(key, now)
    if len(stamps) >= MAX_FAILURES:
        retry_after = max(1, int(stamps[0] + WINDOW_SECONDS - now))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts for this account. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )


def record_failure(key: str) -> None:
    key = _normalise(key)
    if not key:
        return
    now = time.time()
    if len(_failures) >= _MAX_TRACKED_KEYS:
        for stale in [k for k in list(_failures) if not _recent(k, now)]:
            _failures.pop(stale, None)
        if len(_failures) >= _MAX_TRACKED_KEYS:
            _failures.clear()
    _failures.setdefault(key, []).append(now)


def clear(key: str) -> None:
    _failures.pop(_normalise(key), None)


def reset_all() -> None:
    _failures.clear()
