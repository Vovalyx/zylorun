"""
ZyloRun Speed & Scale Load Testing Suite
Simulates realistic concurrent user journeys across public, auth, and authenticated routes
Supports incremental concurrency stages: 50 (smoke), 500, 1000, 2000, 3000 VUs.
Measures RPS, p50, p95, p99 latency, and error rates.
"""

import asyncio
import time
import statistics
import argparse
import sys
import httpx
from typing import List, Dict, Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


async def get_test_token(base_url: str) -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(
                f"{base_url}/auth/login",
                data={"username": "admin", "password": "VovalyxAdmin2026!"}
            )
            if r.status_code == 200:
                return r.json().get("access_token", "")
        except Exception:
            pass
    return ""

async def simulate_user_flow(
    client: httpx.AsyncClient,
    base_url: str,
    user_idx: int,
    stage_duration: float,
    metrics: List[Dict[str, Any]],
    default_token: str = ""
):
    token = default_token
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}
    stop_at = time.time() + stage_duration

    while time.time() < stop_at:
        # Step 1: Public landing & health
        t0 = time.perf_counter()
        try:
            r = await client.get(f"{base_url}/health")
            elapsed = (time.perf_counter() - t0) * 1000.0
            metrics.append({"endpoint": "/health", "status": r.status_code, "latency_ms": elapsed})
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            metrics.append({"endpoint": "/health", "status": 0, "latency_ms": elapsed, "error": str(e)})

        # Step 2: Visitor telemetry tracking
        t0 = time.perf_counter()
        try:
            r = await client.post(
                f"{base_url}/admin/track-visit",
                json={
                    "visitor_id": f"vu_{user_idx}_{int(time.time())}",
                    "path": "/dashboard",
                    "referrer": "https://zylorun.io",
                    "user_agent": "Mozilla/5.0 (ZyloRun Scale Tester)"
                }
            )
            elapsed = (time.perf_counter() - t0) * 1000.0
            metrics.append({"endpoint": "/admin/track-visit", "status": r.status_code, "latency_ms": elapsed})
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            metrics.append({"endpoint": "/admin/track-visit", "status": 0, "latency_ms": elapsed, "error": str(e)})

        # Step 3: Realistic periodic auth (e.g. 5% of users perform login/re-auth)
        if user_idx % 20 == 0:
            t0 = time.perf_counter()
            try:
                r = await client.post(
                    f"{base_url}/auth/login",
                    data={"username": "admin", "password": "VovalyxAdmin2026!"},
                    headers={"X-Forwarded-For": f"198.51.100.{(user_idx % 250) + 1}"}
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/auth/login", "status": r.status_code, "latency_ms": elapsed})
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/auth/login", "status": 0, "latency_ms": elapsed, "error": str(e)})

        # Step 4: Fetch Repositories / Projects (Auth)
        if token:
            t0 = time.perf_counter()
            try:
                r = await client.get(f"{base_url}/repositories/", headers=auth_headers)
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/repositories/", "status": r.status_code, "latency_ms": elapsed})
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/repositories/", "status": 0, "latency_ms": elapsed, "error": str(e)})

            # Step 5: Fast manual code analyzer
            t0 = time.perf_counter()
            try:
                r = await client.post(
                    f"{base_url}/runs/analyze-manual",
                    json={"log_text": "const user_token = 'secret_xyz123';\nfunction query() { return true; }"},
                    headers=auth_headers
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/runs/analyze-manual", "status": r.status_code, "latency_ms": elapsed})
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000.0
                metrics.append({"endpoint": "/runs/analyze-manual", "status": 0, "latency_ms": elapsed, "error": str(e)})

        # Brief user think-time between clicks (realistic browsing pacing)
        await asyncio.sleep(0.1)


async def run_stage(base_url: str, concurrency: int, duration_sec: float) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"[*] Starting Stage: {concurrency} Concurrent Virtual Users | Duration: {duration_sec}s")
    print(f"=======================================================")

    metrics: List[Dict[str, Any]] = []
    limits = httpx.Limits(max_keepalive_connections=500, max_connections=4000)
    timeout = httpx.Timeout(15.0, connect=10.0)

    t_start = time.perf_counter()

    token = await get_test_token(base_url)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        tasks = [
            asyncio.create_task(simulate_user_flow(client, base_url, i, duration_sec, metrics, default_token=token))
            for i in range(concurrency)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    total_time = time.perf_counter() - t_start

    total_requests = len(metrics)
    if total_requests == 0:
        return {"concurrency": concurrency, "requests": 0, "rps": 0, "error_rate": 100.0}

    latencies = [m["latency_ms"] for m in metrics]
    latencies.sort()

    errors = sum(1 for m in metrics if m["status"] >= 500 or m["status"] == 0)
    error_rate = (errors / total_requests) * 100.0
    rps = total_requests / total_time

    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)] if len(latencies) > 0 else 0
    p99 = latencies[int(len(latencies) * 0.99)] if len(latencies) > 0 else 0
    avg_lat = statistics.mean(latencies)
    max_lat = max(latencies)

    # Status distribution
    status_counts: Dict[int, int] = {}
    for m in metrics:
        st = m["status"]
        status_counts[st] = status_counts.get(st, 0) + 1

    print(f"-> Total Requests:     {total_requests:,}")
    print(f"-> Elapsed Time:       {total_time:.2f} s")
    print(f"-> Throughput:         {rps:.1f} Requests/sec (RPS)")
    print(f"-> Latency Average:    {avg_lat:.2f} ms")
    print(f"-> Latency p50:        {p50:.2f} ms")
    print(f"-> Latency p95:        {p95:.2f} ms")
    print(f"-> Latency p99:        {p99:.2f} ms")
    print(f"-> Latency Max:        {max_lat:.2f} ms")
    print(f"-> Errors:             {errors} ({error_rate:.2f}%)")
    print(f"-> Status Distribution: {status_counts}")

    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "duration_sec": round(total_time, 2),
        "rps": round(rps, 1),
        "avg_ms": round(avg_lat, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "max_ms": round(max_lat, 2),
        "errors": errors,
        "error_rate": round(error_rate, 2),
        "status_distribution": status_counts
    }


async def main():
    parser = argparse.ArgumentParser(description="ZyloRun Scale & Load Benchmark")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="Base API URL to test against")
    parser.add_argument("--stages", nargs="+", type=int, default=[50, 500, 1000, 2000, 3000],
                        help="List of concurrency levels to ramp through")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration in seconds per stage")
    args = parser.parse_args()

    print(f"=== ZYLORUN SCALE BENCHMARK HARNESS ===")
    print(f"Target URL: {args.url}")
    print(f"Stages:     {args.stages}")
    print(f"Stage Duration: {args.duration}s each")

    results = []
    for c in args.stages:
        # Cool down between stages to let sockets recycle
        await asyncio.sleep(2)
        res = await run_stage(args.url, c, args.duration)
        results.append(res)

    print("\n\n" + "=" * 80)
    print("FINAL MEASUREMENT SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Concurrency':<12} | {'Requests':<10} | {'RPS':<10} | {'p50 (ms)':<10} | {'p95 (ms)':<10} | {'p99 (ms)':<10} | {'Error %':<8}")
    print("-" * 80)
    for r in results:
        print(f"{r['concurrency']:<12} | {r.get('total_requests', 0):<10} | {r.get('rps', 0):<10} | {r.get('p50_ms', 0):<10} | {r.get('p95_ms', 0):<10} | {r.get('p99_ms', 0):<10} | {r.get('error_rate', 0):<8}%")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
