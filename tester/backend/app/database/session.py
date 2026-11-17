from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine
from app.config import settings

import re
import os

raw_url = settings.DATABASE_URL or "sqlite+aiosqlite:///./risk_passport.db"

# Automatically strip accidental square brackets around password (e.g., :[PASSWORD]@)
if raw_url:
    raw_url = re.sub(r':\[([^\]]+)\]@', r':\1@', raw_url)

# Render & Heroku provide postgres:// URLs; modern SQLAlchemy requires postgresql://
if raw_url.startswith("postgres://"):
    raw_url = raw_url.replace("postgres://", "postgresql://", 1)

# Ensure async engine has an async driver
if raw_url.startswith("postgresql://") and not raw_url.startswith("postgresql+"):
    async_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
elif raw_url.startswith("sqlite://") and not raw_url.startswith("sqlite+"):
    async_url = raw_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
else:
    async_url = raw_url

# Synchronous engine helper for sync threads, background tasks, and seed operations
sync_url = raw_url.replace("+aiosqlite", "").replace("+asyncpg", "")

is_sqlite = "sqlite" in async_url
async_kwargs = {"echo": False}
sync_kwargs = {"echo": False}

def _pool_setting(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


if not is_sqlite:
    # Hosted Postgres poolers cap connections per project (Supabase's session pooler
    # allows about 15 on the smaller plans). Both engines together must stay under that
    # cap, or bursts of traffic get "max clients reached" errors. When every connection
    # is busy, further requests wait up to pool_timeout for a free one instead of failing.
    # Raise these with the DB_* settings only if the database plan allows more connections.
    async_kwargs.update({
        "pool_size": _pool_setting("DB_POOL_SIZE", 6),
        "max_overflow": _pool_setting("DB_MAX_OVERFLOW", 4),
        "pool_timeout": 30,
        "pool_recycle": 1800,
        "pool_pre_ping": True,
        "connect_args": {"timeout": 15},
    })
    sync_kwargs.update({
        "pool_size": _pool_setting("DB_SYNC_POOL_SIZE", 2),
        "max_overflow": _pool_setting("DB_SYNC_MAX_OVERFLOW", 2),
        "pool_timeout": 30,
        "pool_recycle": 1800,
        "pool_pre_ping": True,
        "connect_args": {"connect_timeout": 15},
    })
else:
    async_kwargs.update({
        "pool_pre_ping": True,
    })
    sync_kwargs.update({
        "connect_args": {"check_same_thread": False, "timeout": 30},
        "pool_pre_ping": True,
    })

engine = create_async_engine(async_url, **async_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

try:
    sync_engine = create_engine(sync_url, **sync_kwargs)
except Exception as exc:
    import logging
    logging.getLogger(__name__).warning("Synchronous engine creation with %s failed (%s). Falling back to sqlite:///./sql_app.db.", sync_url, exc)
    sync_engine = create_engine("sqlite:///./sql_app.db", connect_args={"check_same_thread": False, "timeout": 30}, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)

if is_sqlite:
    from sqlalchemy import event
    @event.listens_for(sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    @event.listens_for(engine.sync_engine, "connect")
    def set_async_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
