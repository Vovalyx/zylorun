"""Password hashing: current work factor, compatibility with older hashes, and upgrade on sign-in."""
import bcrypt
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.auth.security import PASSWORD_HASH_ROUNDS, get_password_hash, password_needs_rehash, verify_password
from app.database.models import Base, User
from app.database.session import get_db
from app.main import app


def test_new_hashes_use_the_configured_work_factor():
    hashed = get_password_hash("Sample-password-1")
    assert hashed.split("$")[2] == f"{PASSWORD_HASH_ROUNDS:02d}"
    assert verify_password("Sample-password-1", hashed)
    assert not password_needs_rehash(hashed)


def test_older_stronger_hashes_still_verify_and_are_flagged_for_upgrade():
    old = bcrypt.hashpw(b"Sample-password-1", bcrypt.gensalt(12)).decode()
    assert verify_password("Sample-password-1", old)
    assert password_needs_rehash(old)
    assert not password_needs_rehash("not-a-bcrypt-hash")


@pytest.mark.asyncio
async def test_sign_in_upgrades_an_old_hash_once():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    old_hash = bcrypt.hashpw(b"Sample-password-1", bcrypt.gensalt(12)).decode()
    async with Session() as db:
        db.add(User(id=1, username="upgrade_me", email="upgrade_me@example.com", hashed_password=old_hash, is_active=True))
        await db.commit()

    async def override_get_db():
        async with Session() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/auth/login", data={"username": "upgrade_me", "password": "Sample-password-1"})
            assert res.status_code == 200
            async with Session() as db:
                stored = (await db.get(User, 1)).hashed_password
            assert stored != old_hash
            assert not password_needs_rehash(stored)
            assert verify_password("Sample-password-1", stored)
            # the upgraded hash keeps working
            assert (await client.post("/auth/login", data={"username": "upgrade_me", "password": "Sample-password-1"})).status_code == 200
            assert (await client.post("/auth/login", data={"username": "upgrade_me", "password": "wrong-password"})).status_code == 401
    finally:
        app.dependency_overrides.clear()
