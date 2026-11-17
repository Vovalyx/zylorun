import os
from dotenv import load_dotenv
load_dotenv()
from pydantic_settings import BaseSettings, SettingsConfigDict

# Placeholder values that must never be used to sign or encrypt anything.
INSECURE_SECRET_KEYS = {"", "your-super-secret-key"}
INSECURE_WEBHOOK_SECRETS = {"", "super-secret-webhook-key"}
INSECURE_ENCRYPTION_KEYS = {"", "uE2N2wF5bCq-H6sVlqQhM5mZl3fA7xP4V2bJ0rA1h10="}


class Settings(BaseSettings):
    PROJECT_NAME: str = "Zylorun"
    DATABASE_URL: str = (
        os.getenv("DATABASE_URL")
        or os.getenv("DATABAE_URL")
        or "sqlite+aiosqlite:///./risk_passport.db"
    )
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    GITHUB_OAUTH_STATE_TTL_SECONDS: int = 600
    SCAN_TIMEOUT_SECONDS: int = 120
    CRON_SECRET: str = os.getenv("ZYLORUN_CRON_SECRET", os.getenv("GITFLOW_CRON_SECRET", ""))
    MAX_COMMITS_PER_POLL: int = int(os.getenv("MAX_COMMITS_PER_POLL", "10"))
    MAX_POLLING_RUNTIME_SECONDS: int = int(os.getenv("MAX_POLLING_RUNTIME_SECONDS", "240"))
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))
    GITHUB_TOKEN_ENCRYPTION_KEY: str = os.getenv("GITHUB_TOKEN_ENCRYPTION_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini")

    # Bootstrap administrator. The password is never stored in source code:
    # it is read from the environment and the account is disabled when it is unset.
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")

    # Password reset e-mail delivery (optional). Without SMTP no reset link can be sent.
    PASSWORD_RESET_TOKEN_MINUTES: int = int(os.getenv("PASSWORD_RESET_TOKEN_MINUTES", "30"))
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

import json
import logging
import secrets
import base64

logger = logging.getLogger(__name__)

_DEV_SECRETS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".dev_secrets.json")


def is_production(config) -> bool:
    return str(getattr(config, "ENVIRONMENT", "")).strip().lower() in {"production", "prod"}


def _load_dev_secrets() -> dict:
    try:
        with open(_DEV_SECRETS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_dev_secrets(data: dict) -> None:
    try:
        with open(_DEV_SECRETS_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except Exception:
        # Read-only filesystem: the generated values simply live for this process only.
        pass


def database_kind(config) -> str:
    """'postgresql' or 'sqlite' - the engine only, never the address or credentials."""
    url = str(getattr(config, "DATABASE_URL", "") or "").strip().lower()
    if url.startswith("postgres"):
        return "postgresql"
    if url.startswith("sqlite") or not url:
        return "sqlite"
    return url.split(":", 1)[0].split("+", 1)[0]


def validate_security_settings(config) -> None:
    """Refuse to start in production with missing or placeholder secrets.

    In development, random secrets are generated once and kept in a local,
    git-ignored file so sessions survive a server reload. No secret value is
    ever taken from source code.
    """
    missing = []
    if (config.SECRET_KEY or "") in INSECURE_SECRET_KEYS:
        missing.append("SECRET_KEY")
    if (config.GITHUB_WEBHOOK_SECRET or "") in INSECURE_WEBHOOK_SECRETS:
        missing.append("GITHUB_WEBHOOK_SECRET")
    if (config.GITHUB_TOKEN_ENCRYPTION_KEY or "") in INSECURE_ENCRYPTION_KEYS:
        missing.append("GITHUB_TOKEN_ENCRYPTION_KEY")
    if not (config.CRON_SECRET or ""):
        missing.append("CRON_SECRET")

    if is_production(config):
        if missing:
            raise RuntimeError(
                "Refusing to start in production: set strong, unique values for "
                + ", ".join(missing)
                + " (CRON_SECRET is read from ZYLORUN_CRON_SECRET)."
            )
        origins = [o.strip() for o in str(config.FRONTEND_URL or "").split(",") if o.strip()]
        if not origins or any(not o.lower().startswith("https://") for o in origins):
            raise RuntimeError(
                "Refusing to start in production: set FRONTEND_URL to use HTTPS origins "
                "(comma separated, no wildcard)."
            )
        database_url = getattr(config, "DATABASE_URL", None)
        if database_url is not None and str(database_url).strip().lower().startswith("sqlite"):
            raise RuntimeError(
                "Refusing to start in production: DATABASE_URL is not set, so the server would use a "
                "local SQLite file that is erased on every deploy. Set DATABASE_URL to the PostgreSQL database."
            )
        return

    if database_kind(config) == "sqlite" and hasattr(config, "DATABASE_URL"):
        logger.warning(
            "DATABASE_URL is not set: using a local SQLite file. On hosts with temporary disks "
            "(Render, containers) every account and scan is erased on each deploy or restart."
        )

    if not missing:
        return

    stored = _load_dev_secrets()
    generators = {
        "SECRET_KEY": lambda: secrets.token_urlsafe(48),
        "GITHUB_WEBHOOK_SECRET": lambda: secrets.token_hex(24),
        "GITHUB_TOKEN_ENCRYPTION_KEY": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "CRON_SECRET": lambda: secrets.token_hex(24),
    }
    changed = False
    for name in missing:
        value = stored.get(name)
        if not value:
            value = generators[name]()
            stored[name] = value
            changed = True
        setattr(config, name, value)
    if changed:
        _save_dev_secrets(stored)
    logger.warning(
        "Development mode: generated local secrets for %s. Set them in the environment before deploying.",
        ", ".join(missing),
    )

validate_security_settings(settings)
