import asyncio
import asyncpg

async def test_pooler():
    regions = ["ap-south-1", "ap-southeast-1", "us-east-1", "eu-central-1"]
    ports = [5432, 6543]
    user = "postgres.zrtplsfswxegtigdvery"
    password = "Fm7P8s7umt4OqqWv"
    database = "postgres"

    for r in regions:
        host = f"aws-0-{r}.pooler.supabase.com"
        for p in ports:
            print(f"Testing {host}:{p}...")
            try:
                conn = await asyncpg.connect(
                    host=host,
                    port=p,
                    user=user,
                    password=password,
                    database=database,
                    timeout=5
                )
                print(f"SUCCESS! Connected to Supabase at {host}:{p}!")
                val = await conn.fetchval("SELECT 1")
                print("Query SELECT 1 returned:", val)
                await conn.close()
                return host, p
            except Exception as e:
                print(f"  Failed: {e}")
    return None, None

if __name__ == "__main__":
    asyncio.run(test_pooler())
