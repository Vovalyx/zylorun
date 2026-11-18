from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database.session import engine, Base
from app.api.routes import (
    auth,
    repositories,
    webhooks,
    notifications,
    admin,
    project_hub,
    targets,
    commands,
    runs,
    reports,
    system_tests,
    contact,
    fixes
)
# import models to ensure they are registered with Base metadata
from app.database import models

import asyncio
import logging

logger = logging.getLogger(__name__)

def _alembic_config():
    from alembic.config import Config
    import os
    backend_dir = os.path.dirname(os.path.dirname(__file__))
    alembic_cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    # Set the script location manually just in case
    alembic_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    return alembic_cfg


def adopt_existing_schema() -> None:
    """Brings a database that was built outside Alembic up to the current models.

    Earlier builds created tables with create_all() and ad-hoc ALTER statements, so
    such a database has the tables but no (or an outdated) migration record, and a
    normal upgrade stops with "already exists". This only ever ADDS what is missing
    (tables, then columns as nullable); it never drops or rewrites anything. It then
    verifies every model table and column exists and raises if one does not.
    """
    from sqlalchemy import inspect, text
    from app.database.session import sync_engine, Base
    from app.database import models  # noqa: F401  (registers every table)

    Base.metadata.create_all(bind=sync_engine)

    inspector = inspect(sync_engine)
    quote = sync_engine.dialect.identifier_preparer.quote
    added = []
    with sync_engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in existing:
                    column_type = column.type.compile(dialect=sync_engine.dialect)
                    conn.execute(text(f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(column.name)} {column_type}"))
                    added.append(f"{table.name}.{column.name}")

    inspector = inspect(sync_engine)
    tables = set(inspector.get_table_names())
    missing = []
    for table in Base.metadata.sorted_tables:
        if table.name not in tables:
            missing.append(table.name)
            continue
        present = {c["name"] for c in inspector.get_columns(table.name)}
        missing.extend(f"{table.name}.{c.name}" for c in table.columns if c.name not in present)
    if missing:
        raise RuntimeError("Database schema could not be brought up to date; still missing: " + ", ".join(missing[:10]))
    if added:
        logger.warning("Added columns missing from the existing database: %s", ", ".join(added))


def run_migrations():
    """Applies migrations. If the upgrade fails because the database was created
    outside Alembic, the existing schema is completed, verified and recorded as
    current; if it cannot be verified, the error is raised and startup stops."""
    from alembic import command

    alembic_cfg = _alembic_config()
    try:
        command.upgrade(alembic_cfg, "head")
        return
    except Exception as upgrade_error:
        logger.warning(
            "Migration upgrade failed (%s: %s). Checking whether this database was created outside Alembic...",
            upgrade_error.__class__.__name__, str(upgrade_error).splitlines()[0][:200],
        )
        try:
            adopt_existing_schema()
            command.stamp(alembic_cfg, "head")
        except Exception as adopt_error:
            logger.error("The existing schema could not be adopted: %s", adopt_error)
            raise upgrade_error
        logger.warning("Existing schema verified against the models and recorded as the current migration.")

DISABLED_PASSWORD_HASH = "!disabled"
MIN_ADMIN_PASSWORD_LENGTH = 12

def ensure_bootstrap_admin():
    """Creates or updates the bootstrap administrator from environment variables.

    ADMIN_PASSWORD is the only source of this account's password. When it is not
    set (or too short) the account cannot sign in at all, so a database that was
    seeded by an older build with a publicly known password is locked on startup.
    """
    from sqlalchemy import func
    from app.config import settings
    from app.database.session import SessionLocal
    from app.database.models import User
    from app.auth.security import get_password_hash, password_needs_rehash, verify_password

    username = (settings.ADMIN_USERNAME or "admin").strip()
    email = (settings.ADMIN_EMAIL or "").strip().lower()
    password = settings.ADMIN_PASSWORD or ""

    db = SessionLocal()
    try:
        admin_u = db.query(User).filter(func.lower(User.username) == username.lower()).first()

        if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
            if admin_u and admin_u.hashed_password != DISABLED_PASSWORD_HASH:
                admin_u.hashed_password = DISABLED_PASSWORD_HASH
                db.commit()
            logger.warning(
                "ADMIN_PASSWORD is not set (minimum %s characters). The '%s' administrator account is disabled until it is.",
                MIN_ADMIN_PASSWORD_LENGTH, username,
            )
            return

        if not admin_u:
            admin_email = email or f"{username.lower()}@zylorun.local"
            if db.query(User).filter(func.lower(User.email) == admin_email).first():
                logger.error("Cannot create administrator '%s': ADMIN_EMAIL is already used by another account.", username)
                return
            db.add(User(
                username=username,
                email=admin_email,
                hashed_password=get_password_hash(password),
                role="Admin",
                is_active=True,
            ))
            db.commit()
            return

        changed = False
        if admin_u.role != "Admin":
            admin_u.role = "Admin"; changed = True
        if not admin_u.is_active:
            admin_u.is_active = True; changed = True
        if password_needs_rehash(admin_u.hashed_password) or not verify_password(password, admin_u.hashed_password):
            admin_u.hashed_password = get_password_hash(password); changed = True
        if changed:
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("Could not prepare the administrator account: %s", exc.__class__.__name__)
    finally:
        db.close()

async def background_repo_poller():
    """Continuously polls active repositories for new commits in the background.
    Runs periodically every 60 seconds with lock protection and error isolation.
    """
    import os
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("TESTING"):
        return

    await asyncio.sleep(15)  # Grace period after boot
    while True:
        try:
            from app.api.routes.admin import execute_polling_cycle
            await execute_polling_cycle()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Background repository polling cycle encountered error: %s", exc)
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break


async def background_visitor_flush():
    while True:
        try:
            await asyncio.sleep(2)
            from app.api.routes.admin import flush_visitor_logs_batch
            await flush_visitor_logs_batch()
        except asyncio.CancelledError:
            break
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        # A failed migration must stop the application: running on a half-migrated
        # schema hides the problem and corrupts data later.
        await asyncio.wait_for(asyncio.to_thread(run_migrations), timeout=120.0)
        logger.info("Successfully ran database migrations.")

        try:
            await asyncio.wait_for(asyncio.to_thread(ensure_bootstrap_admin), timeout=30.0)
        except Exception as admin_err:
            logger.error("Administrator bootstrap did not complete: %s", admin_err.__class__.__name__)

        try:
            from app.database.session import SessionLocal
            from app.database.models import CommandConfig
            import json
            def _seed():
                db = SessionLocal()
                try:
                    if db.query(CommandConfig).count() == 0:
                        defaults = [
                            CommandConfig(
                                name="Ping Latency Diagnostic",
                                executable="ping",
                                allowed_args=json.dumps(["-c", "4", "-n", "4"]),
                                timeout_seconds=30,
                                regex_rules=json.dumps({
                                    "rules": [
                                        {"pattern": r"100% packet loss|Destination host unreachable", "severity": "Critical", "message": "Host is completely unreachable."},
                                        {"pattern": r"Request timed out", "severity": "Warning", "message": "Packet loss detected."}
                                    ]
                                })
                            ),
                            CommandConfig(
                                name="HTTPS TLS Header Audit",
                                executable="curl",
                                allowed_args=json.dumps(["-I", "-s", "--max-time", "15"]),
                                timeout_seconds=30,
                                regex_rules=json.dumps({
                                    "rules": [
                                        {"pattern": r"HTTP/(?:1\.1|2|3)\s+(?:4\d\d|5\d\d)", "severity": "Warning", "message": "Non-200 HTTP response status returned by target."},
                                        {"pattern": r"Strict-Transport-Security", "severity": "Info", "message": "HSTS security header detected."}
                                    ]
                                })
                            ),
                            CommandConfig(
                                name="Nmap Security Port Scan",
                                executable="nmap",
                                allowed_args=json.dumps(["-F", "-sT", "--top-ports", "20"]),
                                timeout_seconds=120,
                                regex_rules=json.dumps({
                                    "rules": [
                                        {"pattern": r"22/open", "severity": "Warning", "message": "SSH port 22 is publicly exposed."},
                                        {"pattern": r"23/open|21/open", "severity": "Critical", "message": "Insecure legacy protocol (Telnet/FTP) detected."}
                                    ]
                                })
                            )
                        ]
                        for c in defaults:
                            db.add(c)
                        db.commit()
                except Exception as exc:
                    logger.warning("Could not seed default configs/users: %s", exc)
                finally:
                    db.close()
            await asyncio.wait_for(asyncio.to_thread(_seed), timeout=8.0)
        except Exception as exc:
            logger.warning("Default seeding encountered exception: %s", exc)

        poller_task = asyncio.create_task(background_repo_poller())
        flush_task = asyncio.create_task(background_visitor_flush())
        yield
        flush_task.cancel()
        poller_task.cancel()
        try:
            await flush_task
            await poller_task
        except (asyncio.CancelledError, Exception):
            pass
    finally:
        await engine.dispose()


app = FastAPI(title="Zylorun", lifespan=lifespan)

from app.config import settings

cors_origins = [
    "https://zylorun-five.vercel.app",
    "https://zylorun.vercel.app",
    "https://vovalyx.in",
    "https://www.vovalyx.in",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

if settings.FRONTEND_URL and settings.FRONTEND_URL != "*":
    for origin in settings.FRONTEND_URL.split(","):
        origin = origin.strip()
        if origin and origin not in cors_origins:
            cors_origins.append(origin)

from app.config import is_production

# Only explicitly listed origins are trusted. LAN addresses are accepted in
# development so phones on the same network can reach a local dev server.
_DEV_LAN_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=None if is_production(settings) else _DEV_LAN_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

import time
from collections import defaultdict
from fastapi.responses import JSONResponse
from fastapi.middleware.gzip import GZipMiddleware

app.add_middleware(GZipMiddleware, minimum_size=1000)

_RATE_LIMIT_BUCKETS = defaultdict(list)
_RATE_LIMIT_MAX_AUTH = 120  # per address per minute; brute force is stopped by the per-account lockout
_RATE_LIMIT_WINDOW = 60.0
_LAST_ERROR_LOG_TIME = 0.0

_RATE_LIMITED_PATHS = {
    "/auth/login", "/auth/register", "/auth/forgot-password", "/auth/reset-password",
    "/admin/login", "/contact", "/api/v1/contact",
}
_RATE_LIMIT_MAX_KEYS = 50000


def client_address(request: Request) -> str:
    """Best-effort client address for rate limiting.

    The left-most X-Forwarded-For entry is supplied by the caller and can be
    forged, so the right-most entry (appended by our own reverse proxy) is used.
    Per-account lockout in app.auth.throttle does not depend on this value.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    path = request.url.path.rstrip("/") or "/"
    if request.method == "POST" and path in _RATE_LIMITED_PATHS:
        client_ip = client_address(request)

        now = time.time()
        if len(_RATE_LIMIT_BUCKETS) > _RATE_LIMIT_MAX_KEYS:
            for key in [k for k, stamps in list(_RATE_LIMIT_BUCKETS.items()) if not stamps or stamps[-1] <= now - _RATE_LIMIT_WINDOW]:
                _RATE_LIMIT_BUCKETS.pop(key, None)
        timestamps = [t for t in _RATE_LIMIT_BUCKETS[client_ip] if t > now - _RATE_LIMIT_WINDOW]
        if len(timestamps) >= _RATE_LIMIT_MAX_AUTH:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many authentication requests. Please try again shortly."},
                headers={"Retry-After": "60"}
            )
        timestamps.append(now)
        _RATE_LIMIT_BUCKETS[client_ip] = timestamps

    return await call_next(request)

async def _record_system_error(err_type: str, severity: str, message: str, path: str, method: str, status_code: int, stack_trace: str = None):
    try:
        from app.database.models import SystemErrorLog
        from app.database.session import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            err_entry = SystemErrorLog(
                error_type=err_type,
                severity=severity,
                message=message,
                stack_trace=stack_trace,
                path=path,
                method=method,
                status_code=status_code
            )
            session.add(err_entry)
            await session.commit()
    except Exception:
        pass

@app.middleware("http")
async def error_and_system_monitor_middleware(request: Request, call_next):
    global _LAST_ERROR_LOG_TIME
    try:
        response = await call_next(request)
        if response.status_code >= 500:
            now = time.time()
            if now - _LAST_ERROR_LOG_TIME > 0.1:  # Throttle DB error log bursts to max 10/sec
                _LAST_ERROR_LOG_TIME = now
                asyncio.create_task(_record_system_error(
                    "API_SERVER_ERROR", "CRITICAL",
                    f"HTTP {response.status_code} occurred on {request.method} {request.url.path}",
                    request.url.path, request.method, response.status_code
                ))
        return response
    except Exception as exc:
        import traceback
        now = time.time()
        if now - _LAST_ERROR_LOG_TIME > 0.1:
            _LAST_ERROR_LOG_TIME = now
            asyncio.create_task(_record_system_error(
                "UNHANDLED_EXCEPTION", "CRITICAL",
                str(exc), request.url.path, request.method, 500, traceback.format_exc()
            ))
        raise exc

app.include_router(auth.router)
app.include_router(repositories.router)
app.include_router(project_hub.router)
app.include_router(webhooks.router)
app.include_router(notifications.router)
app.include_router(admin.router)
app.include_router(targets.router)
app.include_router(commands.router)
app.include_router(runs.router)
app.include_router(reports.router)
app.include_router(system_tests.router)
app.include_router(contact.router)
app.include_router(fixes.router)

@app.get("/api/v1/health")
@app.get("/health")
async def health_check():
    from app.config import database_kind
    kind = database_kind(settings)
    body = {
        "status": "healthy",
        "service": "Zylorun",
        "version": "2.1.0",
        "environment": "production" if is_production(settings) else "development",
        "database": kind,
    }
    if kind == "sqlite":
        # Shown on purpose: a hosted deployment on SQLite loses all accounts on every deploy.
        body["warning"] = "Data is stored in a local SQLite file (DATABASE_URL is unset or points to SQLite); it is lost when the host's disk is reset."
    return body

@app.get("/")
async def root():
    return {"message": "Welcome to Zylorun Autonomous Risk & Assurance API", "version": "2.1.0"}
