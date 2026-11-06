import asyncio
import os
import sys

# Configure Tokyo ap-northeast-1 Supabase Connection Pooler URL (IPv4 & IPv6 universal support)
os.environ["DATABASE_URL"] = "postgresql+asyncpg://postgres.zrtplsfswxegtigdvery:Fm7P8s7umt4OqqWv@aws-0-ap-northeast-1.pooler.supabase.com:5432/postgres"

from app.database.session import engine, Base
from app.database.models import User, Repository, VisitorLog, ContactMessage
from sqlalchemy import select, text

async def test_connection():
    print("=" * 60)
    print("  VERIFYING RESUMED SUPABASE POSTGRESQL DATABASE")
    print("=" * 60)
    try:
        async with engine.begin() as conn:
            ver = await conn.execute(text("SELECT version()"))
            pg_version = ver.scalar()
            print("[PASS] Successfully connected to Supabase PostgreSQL database.")
            print(f"       Engine Version: {pg_version[:55]}")

        # Test selecting users
        from app.database.session import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            u_res = await session.execute(select(User))
            users = u_res.scalars().all()
            print(f"[PASS] Retrieved {len(users)} registered users from Supabase:")
            for u in users:
                print(f"       - ID {u.id}: {u.username} ({u.email}) [Role: {u.role}]")

            r_res = await session.execute(select(Repository))
            repos = r_res.scalars().all()
            print(f"[PASS] Retrieved {len(repos)} registered repositories from Supabase.")

        print("=" * 60)
        print("  SUPABASE DATABASE IS 100% ONLINE, HEALTHY, AND OPERATIONAL!")
        print("=" * 60)
    except Exception as e:
        print(f"[FAIL] Error connecting to Supabase: {e}")
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(test_connection())
