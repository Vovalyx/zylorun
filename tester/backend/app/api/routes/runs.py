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

MAX_MANUAL_LOG_BYTES = 2 * 1024 * 1024  # 2 MB of text is far beyond any real log paste

@router.post("/analyze-manual")
async def analyze_manual_log(req: ManualLogRequest, current_user: User = Depends(get_current_user)):
    if len(req.log_text or "") > MAX_MANUAL_LOG_BYTES or len(req.log_text_b64 or "") > MAX_MANUAL_LOG_BYTES * 2:
        raise HTTPException(status_code=413, detail="Log is too large to analyze (limit 2 MB).")
    raw_text = req.log_text or ""
    if req.log_text_b64:
        try:
            raw_text = base64.b64decode(req.log_text_b64).decode("utf-8", errors="ignore")
        except Exception:
            pass
    if len(raw_text) > MAX_MANUAL_LOG_BYTES:
        raise HTTPException(status_code=413, detail="Log is too large to analyze (limit 2 MB).")
    lines = raw_text.replace("\r", "").split("\n")
    findings = []
    status_result = "Pass"
    current_file = "General"

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        line_lower = line_clean.lower()

        # Detect file boundaries in concatenated archive logs
        if line_clean.startswith("--- File:") or line_clean.startswith("File:") or line_clean.endswith(".js") or line_clean.endswith(".ts") or line_clean.endswith(".py"):
            current_file = line_clean.replace("--- File: ", "").replace(" ---", "").strip()
            continue

        # Heuristics for critical security vulnerabilities and code risks
        is_sqli = ("select " in line_lower and " from " in line_lower and "+" in line_lower) or ("cursor.execute(" in line_lower and ("+" in line_lower or "%" in line_lower))
        is_secret = any(k in line_lower for k in ["aws_secret", "private_key", "secret_key", "bearer ", "api_key ="]) or ("password" in line_lower and "=" in line_lower and not "input" in line_lower)
        is_rce = any(k in line_lower for k in ["eval(", "exec(", "os.system(", "subprocess.call(", "subprocess.popen("]) and ("shell=true" in line_lower or "eval" in line_lower or "exec" in line_lower)
        is_xss = "innerhtml" in line_lower or "dangerouslysetinnerhtml" in line_lower or "document.write(" in line_lower

        is_critical = is_sqli or is_secret or is_rce or is_xss or any(k in line_lower for k in [
            "error", "critical", "fatal", "secret", "password", "token", "leak", "xss", "rce", "sql injection", "dangerously", "cve-"
        ])
        is_warning = any(k in line_lower for k in [
            "warning", "warn", "deprecated", "disclosure", "sast", "sca", "header", "leftover", "todo", "fixme", "insecure", "debug = true", "allow_origins=[\"*\"]"
        ])

        if is_critical:
            flaw_type = "SQL Injection" if is_sqli else "Hardcoded Secret" if is_secret else "Remote Code Execution (RCE)" if is_rce else "Cross-Site Scripting (XSS)" if is_xss else "Critical Finding"
            findings.append({
                "severity": "Critical",
                "message": f"{current_file} -> [{flaw_type}] {line_clean}",
                "recommendation": f"Critical {flaw_type} detected. Sanitize input or remove exposed secret immediately."
            })
            status_result = "Fail"
        elif is_warning:
            findings.append({
                "severity": "Warning",
                "message": f"{current_file} -> {line_clean}",
                "recommendation": "Security advisory or best practice rule violation."
            })
            if status_result == "Pass":
                status_result = "Warning"

    # Contextual remediation enrichment
    for finding in findings:
        msg = finding["message"].lower()
        file_part = finding["message"].split(" -> ")[0] if " -> " in finding["message"] else current_file
        file_name = file_part.split("/")[-1].split("\\")[-1]

        if "identifier directly after number" in msg:
            finding["recommendation"] = f"Syntax error in '{file_name}': A number literal is placed directly adjacent to an identifier. Separate tokens with a space or quotation marks."
        elif "unexpected token <" in msg:
            finding["recommendation"] = f"JSX parse error in '{file_name}': Parser encountered HTML tags without JSX transformation enabled. Configure a React/JSX transpiler."
        elif "empty block statement" in msg:
            finding["recommendation"] = f"Empty code block in '{file_name}': Remove redundant empty braces {{}} or add a comment explaining why it is intentionally vacant."
        elif "never used" in msg:
            finding["recommendation"] = f"Unused variable in '{file_name}': Remove the unreferenced variable to reduce bundle weight and prevent logical oversights."
        elif "non literal argument" in msg or "path traversal" in msg:
            finding["recommendation"] = f"Path Traversal risk in '{file_name}': Dynamic user input is passed directly to filesystem access. Validate paths against a safe root directory."
        elif "object injection" in msg or "prototype" in msg:
            finding["recommendation"] = f"Prototype Pollution hazard in '{file_name}': Untrusted keys are accessed on dynamic objects. Freeze critical prototypes or use Map structures."
        elif "secret" in msg or "password" in msg or "token" in msg:
            finding["recommendation"] = f"Hardcoded credential in '{file_name}': Exposed credentials in source code. Immediately revoke and migrate secret to an environment variable."
        elif "xss" in msg or "dangerouslysetinnerhtml" in msg or "eval(" in msg:
            finding["recommendation"] = f"XSS / Code execution vulnerability in '{file_name}': Dangerously evaluating unescaped strings. Use safe encoding or sanitization libraries."

    return {"status": status_result, "findings": findings}

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
