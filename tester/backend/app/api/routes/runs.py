import asyncio
import json
import time
import ipaddress
import base64
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, Dict, Any

from app.database.session import get_db, SessionLocal
from app.database.models import RunHistory, CommandConfig, Target, User
from app.auth.deps import get_current_user
from app.services.runner import CommandRunner
from app.ai.service import AIService

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/runs", tags=["runs"])

# ----------------- Manual Log & ZIP Analyzer -----------------

class ManualLogRequest(BaseModel):
    log_text: Optional[str] = None
    log_text_b64: Optional[str] = None
    # Name of the uploaded file (e.g. "app.log", "views.py"). Decides whether the text is
    # read as a log, source code or configuration. Archives carry "--- File: name ---" headers.
    file_name: Optional[str] = None

MAX_MANUAL_LOG_BYTES = 2 * 1024 * 1024  # 2 MB of text is far beyond any real log paste

@router.post("/analyze-manual")
async def analyze_manual_log(req: ManualLogRequest, current_user: User = Depends(get_current_user)):
    if len(req.log_text or "") > MAX_MANUAL_LOG_BYTES or len(req.log_text_b64 or "") > MAX_MANUAL_LOG_BYTES * 2:
        raise HTTPException(status_code=413, detail="Log is too large to analyze (limit 2 MB).")
    raw_text = req.log_text or ""
    if req.log_text_b64:
        try:
            raw_text = base64.b64decode(req.log_text_b64).decode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(status_code=400, detail="log_text_b64 is not valid base64.")
    if len(raw_text) > MAX_MANUAL_LOG_BYTES:
        raise HTTPException(status_code=413, detail="Log is too large to analyze (limit 2 MB).")
    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="Nothing to analyze: the text is empty.")

    from app.services.log_analyzer import analyze_text

    file_name = (req.file_name or "").strip()[:255] or None
    # The analysis is CPU-bound; keep it off the event loop so other requests are not blocked.
    return await asyncio.to_thread(analyze_text, raw_text, file_name)

# ----------------- AI Fix Generation -----------------

class GenerateFixRequest(BaseModel):
    findings: Optional[List[Dict[str, Any]]] = []
    custom_prompt: Optional[str] = None

MAX_FIX_PROMPT_CHARS = 6000
MAX_FIX_FINDINGS = 40

@router.post("/generate-fix")
async def generate_comprehensive_fix(
    req: GenerateFixRequest,
    current_user: User = Depends(get_current_user)
):
    ai_service = AIService()
    provider = ai_service.get_provider()

    if len(req.custom_prompt or "") > MAX_FIX_PROMPT_CHARS:
        raise HTTPException(status_code=413, detail=f"Prompt is too long (limit {MAX_FIX_PROMPT_CHARS} characters).")

    if req.custom_prompt and req.custom_prompt.strip():
        user_prompt = req.custom_prompt.strip()
    else:
        user_prompt = "I have the following security and code findings that need remediation:\n\n"
        for idx, f in enumerate((req.findings or [])[:MAX_FIX_FINDINGS]):
            user_prompt += f"{idx+1}. [{str(f.get('severity', 'Warning'))[:20]}] {str(f.get('message', ''))[:600]}\n"
            if f.get('recommendation'):
                user_prompt += f"   Context: {str(f.get('recommendation'))[:400]}\n"
        user_prompt += "\nPlease provide production-ready code fixes and explanations formatted in clean Markdown."

    system_prompt = (
        "You are an expert security engineer and code reviewer. "
        "Analyze the provided findings and output precise, copy-pasteable remediation patches. "
        "Explain root causes concisely and adhere to security best practices."
    )

    try:
        res = await provider.generate_completion(prompt=user_prompt, system_prompt=system_prompt)
        text = res.get("content") or res.get("response") or res.get("text") or "No remediation generated."
        return {"response": text}
    except Exception as exc:
        logger.warning("AI remediation request failed: %s", exc.__class__.__name__)
        return {"response": "AI remediation service is unavailable right now. Please try again later."}

# ----------------- Safe URL Speed & Latency Test -----------------

class UrlSpeedTestRequest(BaseModel):
    url: str

def _is_public_ip(ip) -> bool:
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
    )


def is_safe_external_url(target_url: str) -> bool:
    """Accepts only http(s) URLs whose host is, and resolves only to, public addresses."""
    import socket
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname or parsed.username or parsed.password:
            return False
        if hostname.lower() in ("localhost", "0.0.0.0") or hostname.lower().endswith((".localhost", ".local", ".internal")):
            return False
        try:
            return _is_public_ip(ipaddress.ip_address(hostname))
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        except Exception:
            return False
        addresses = {info[4][0] for info in infos}
        return bool(addresses) and all(_is_public_ip(ipaddress.ip_address(a)) for a in addresses)
    except Exception:
        return False

MAX_SPEED_TEST_REDIRECTS = 5
MAX_SPEED_TEST_BYTES = 5 * 1024 * 1024

_HTTP_CLIENT_LIMITS = httpx.Limits(max_keepalive_connections=25, max_connections=150)
_HTTP_CLIENT: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None or _HTTP_CLIENT.is_closed:
        _HTTP_CLIENT = httpx.AsyncClient(limits=_HTTP_CLIENT_LIMITS, timeout=12.0, follow_redirects=False)
    return _HTTP_CLIENT

@router.post("/url-speed-test")
async def analyze_url_speed(
    req: UrlSpeedTestRequest,
    current_user: User = Depends(get_current_user)
):
    raw_url = req.url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    if len(raw_url) > 2048 or not await asyncio.to_thread(is_safe_external_url, raw_url):
        return {
            "success": False,
            "url": raw_url,
            "status_code": 0,
            "total_time_ms": 0,
            "ttfb_ms": 0,
            "content_size_bytes": 0,
            "speed_grade": "RED",
            "status_text": "Request Rejected: Prohibited internal or invalid target host (SSRF Protection).",
            "badge_color": "#ff3366",
            "server": "N/A",
            "content_type": "N/A",
            "encoding": "N/A",
            "redirects": 0
        }

    headers = {
        "User-Agent": "SecRunner-SpeedAudit/2.0 (Security-Performance-Bot)"
    }

    start_time = time.perf_counter()
    try:
        client = get_http_client()
        # Redirects are followed by hand so every hop is checked against the same rules.
        current_url = raw_url
        redirects = 0
        ttfb_ms = None
        while True:
            async with client.stream("GET", current_url, headers=headers) as res:
                if ttfb_ms is None:
                    ttfb_ms = round((time.perf_counter() - start_time) * 1000)
                if res.status_code in (301, 302, 303, 307, 308) and res.headers.get("location"):
                    next_url = str(res.url.join(res.headers["location"]))
                    redirects += 1
                    if redirects > MAX_SPEED_TEST_REDIRECTS or not await asyncio.to_thread(is_safe_external_url, next_url):
                        raise ValueError("redirect to a disallowed or internal address was blocked")
                    current_url = next_url
                    continue
                content_size = 0
                async for chunk in res.aiter_bytes():
                    content_size += len(chunk)
                    if content_size > MAX_SPEED_TEST_BYTES:
                        break
                status_code = res.status_code
                response_headers = res.headers
                break
        total_time_ms = round((time.perf_counter() - start_time) * 1000)

        if total_time_ms < 1500 and status_code < 400:
            speed_grade = "GREEN"
            status_text = "Optimal / Fast Response"
            badge_color = "#00e676"
        elif total_time_ms <= 3000 and status_code < 400:
            speed_grade = "YELLOW"
            status_text = "Moderate / Average Response"
            badge_color = "#ffab00"
        else:
            speed_grade = "RED"
            status_text = "High Latency / Slow"
            badge_color = "#ff3366"

        return {
            "success": True,
            "url": raw_url,
            "status_code": status_code,
            "total_time_ms": total_time_ms,
            "ttfb_ms": ttfb_ms,
            "content_size_bytes": content_size,
            "speed_grade": speed_grade,
            "status_text": status_text,
            "badge_color": badge_color,
            "server": response_headers.get("server", "Unknown"),
            "content_type": response_headers.get("content-type", "Unknown"),
            "encoding": response_headers.get("content-encoding", "None"),
            "redirects": redirects
        }
    except Exception as exc:
        total_time_ms = round((time.perf_counter() - start_time) * 1000)
        return {
            "success": False,
            "url": raw_url,
            "status_code": 0,
            "total_time_ms": total_time_ms,
            "ttfb_ms": total_time_ms,
            "content_size_bytes": 0,
            "speed_grade": "RED",
            "status_text": f"Connection Failed ({exc.__class__.__name__})",
            "badge_color": "#ff3366",
            "server": "N/A",
            "content_type": "N/A",
            "encoding": "N/A",
            "redirects": 0
        }

# ----------------- WebSocket Live Execution Stream -----------------

WS_POLICY_VIOLATION = 1008

@router.websocket("/ws/{command_id}/{target_id}")
async def websocket_run(websocket: WebSocket, command_id: int, target_id: int):
    """Runs an approved diagnostic tool and streams its output.

    The first client message must carry the caller's access token:
    {"token": "<access token>", "args": [...]}. Nothing is executed and no
    record is created until the token is valid and the target belongs to the caller.
    """
    await websocket.accept()

    try:
        client_msg = await asyncio.wait_for(websocket.receive_text(), timeout=15)
        parsed = json.loads(client_msg)
        if not isinstance(parsed, dict):
            raise ValueError("malformed start message")
    except WebSocketDisconnect:
        return
    except Exception:
        await websocket.send_json({"error": "Authentication required", "status": "Error"})
        await websocket.close(code=WS_POLICY_VIOLATION)
        return

    from app.database.session import AsyncSessionLocal
    from app.auth.deps import get_user_from_token

    async with AsyncSessionLocal() as async_db:
        user = await get_user_from_token(str(parsed.get("token") or ""), async_db)
    if not user:
        await websocket.send_json({"error": "Authentication required", "status": "Error"})
        await websocket.close(code=WS_POLICY_VIOLATION)
        return

    args = parsed.get("args", [])
    if not isinstance(args, list):
        args = []

    # Create synchronous session for subprocess runner
    db = SessionLocal()
    try:
        command = db.query(CommandConfig).filter(CommandConfig.id == command_id).first()
        target = db.query(Target).filter(Target.id == target_id, Target.user_id == user.id).first()

        if not command or not target:
            await websocket.send_json({"error": "Command or Target configuration not found"})
            await websocket.close()
            return

        new_run = RunHistory(
            command_id=command.id,
            target_id=target.id,
            user_id=user.id,
            status="Pending"
        )
        db.add(new_run)
        db.commit()
        db.refresh(new_run)

        await CommandRunner.run_command_stream(new_run.id, command, target, args, db, websocket)

    finally:
        db.close()

# ----------------- Run History Listing -----------------

@router.get("")
@router.get("/")
async def list_runs(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(RunHistory).where(RunHistory.user_id == current_user.id).order_by(RunHistory.id.desc()).limit(50)
    result = await db.execute(query)
    runs = result.scalars().all()
    return [
        {
            "id": r.id,
            "command_id": r.command_id,
            "target_id": r.target_id,
            "status": r.status,
            "start_time": r.start_time,
            "end_time": r.end_time,
            "findings": json.loads(r.findings) if r.findings else []
        }
        for r in runs
    ]
