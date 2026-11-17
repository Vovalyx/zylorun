import asyncio
import json
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.database.models import RunHistory, CommandConfig, Target
from app.services.analyzer import OutputAnalyzer

# RFC-compliant hostname, IPv4, IPv6, or localhost
HOST_REGEX = re.compile(
    r'^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?|localhost)$'
)

# Full shape of an accepted target: [http(s)://]host[:port][/path]
TARGET_REGEX = re.compile(
    r"^(?:https?://)?"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[0-9a-fA-F]*:[0-9a-fA-F:]+|[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)"
    r"(?::\d{1,5})?"
    r"(?:/[A-Za-z0-9._~\-/%]*)?$"
)

# Approved executable allowlist. Only network diagnostic tools are permitted:
# anything that can run code or read/write arbitrary files (python, node, git,
# shells, interpreters) must never be added here.
APPROVED_EXECUTABLES = {
    "ping", "ping.exe",
    "curl", "curl.exe",
    "nmap", "nmap.exe",
    "openssl", "openssl.exe",
}

MAX_ARG_LENGTH = 64
MAX_ARGS = 16


def executable_basename(executable: str) -> str:
    return (executable or "").strip().lower().split("/")[-1].split("\\")[-1]


def is_internal_address(host: str) -> bool:
    """True when the host is, or resolves to, a loopback/private/link-local address."""
    import ipaddress
    import socket

    clean = host.split("://")[-1].split("/")[0].strip("[]")
    if clean.count(":") == 1:
        clean = clean.split(":")[0]
    if clean.lower() == "localhost":
        return True
    candidates = []
    try:
        candidates.append(ipaddress.ip_address(clean))
    except ValueError:
        try:
            for info in socket.getaddrinfo(clean, None):
                candidates.append(ipaddress.ip_address(info[4][0]))
        except Exception:
            return False
    return any(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        for ip in candidates
    )


class CommandRunner:
    @staticmethod
    def validate_target_host(host: str) -> bool:
        """Accepts a bare hostname, IPv4 or IPv6 address, optionally with an http(s) scheme,
        port and path. The whole string must match: input is never "cleaned" into
        something valid, so values such as "${jndi:ldap://x/a}" are rejected outright."""
        if not host or len(host) > 255:
            return False
        match = TARGET_REGEX.match(host.strip())
        if not match:
            return False
        return bool(HOST_REGEX.match(match.group("host")))

    @staticmethod
    async def run_command_stream(
        run_id: int,
        command_config: CommandConfig,
        target: Target,
        args: List[str],
        db: Session,
        websocket=None
    ) -> RunHistory:
        db_run = db.query(RunHistory).filter(RunHistory.id == run_id).first()
        if not db_run:
            raise ValueError(f"RunHistory record {run_id} not found.")

        db_run.status = "Running"
        db.commit()

        # Security check 1: Target host validation
        if not CommandRunner.validate_target_host(target.host):
            db_run.status = "Error"
            db_run.raw_output = f"[SECURITY REJECTION] Target host '{target.host}' failed validation. Refusing execution."
            db_run.findings = json.dumps([{"severity": "Critical", "message": "Invalid or dangerous target host."}])
            db_run.end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            if websocket:
                await websocket.send_json({"error": "Invalid target host pattern", "status": "Error"})
                await websocket.close()
            return db_run

        # Security check 1b: in production the server must not be used to probe its own network
        from app.config import settings, is_production
        if is_production(settings) and await asyncio.to_thread(is_internal_address, target.host):
            db_run.status = "Error"
            db_run.raw_output = "[SECURITY REJECTION] Internal, loopback and private network targets are not allowed."
            db_run.findings = json.dumps([{"severity": "Critical", "message": "Internal network target rejected."}])
            db_run.end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            if websocket:
                await websocket.send_json({"error": "Internal network targets are not allowed", "status": "Error"})
                await websocket.close()
            return db_run

        # Security check 2: Executable check. Only the bare tool name is ever executed,
        # so a stored path can never point at a different binary.
        executable_base = executable_basename(command_config.executable)
        if executable_base != (command_config.executable or "").strip().lower() or executable_base not in APPROVED_EXECUTABLES:
            db_run.status = "Error"
            db_run.raw_output = f"[SECURITY REJECTION] Executable '{command_config.executable}' is not in the approved security tools allowlist."
            db_run.findings = json.dumps([{"severity": "Critical", "message": "Unauthorized executable."}])
            db_run.end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            if websocket:
                await websocket.send_json({"error": "Unauthorized executable", "status": "Error"})
                await websocket.close()
            return db_run

        # Security check 3: Argument allowlist validation
        try:
            allowed_args_list = json.loads(command_config.allowed_args) if isinstance(command_config.allowed_args, str) else command_config.allowed_args
        except Exception:
            allowed_args_list = []

        if not isinstance(allowed_args_list, list):
            allowed_args_list = []
        if not isinstance(args, list):
            args = []

        validated_args = []
        for arg in args[:MAX_ARGS]:
            if isinstance(arg, str) and arg in allowed_args_list:
                validated_args.append(arg)
            else:
                db_run.status = "Error"
                db_run.raw_output = f"[SECURITY REJECTION] Disallowed argument '{arg}' was supplied for tool '{command_config.name}'."
                db_run.findings = json.dumps([{"severity": "High", "message": f"Disallowed argument: {arg}"}])
                db_run.end_time = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
                if websocket:
                    await websocket.send_json({"error": f"Disallowed argument: {arg}", "status": "Error"})
                    await websocket.close()
                return db_run

        clean_host = target.host.split("://")[-1].split("/")[0]
        cmd_args = [executable_base] + validated_args + [clean_host]
        full_output = []

        process = None
        try:
            # shell=False strictly enforced
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=False
            )

            loop = asyncio.get_running_loop()

            async def read_stream_async():
                while True:
                    line = await loop.run_in_executor(None, process.stdout.readline)
                    if not line:
                        break
                    decoded_line = line.strip()
                    full_output.append(decoded_line)
                    if websocket:
                        try:
                            await websocket.send_json({"stream": "stdout", "data": decoded_line})
                        except Exception:
                            pass

            timeout_sec = min(max(command_config.timeout_seconds, 5), 300)
            await asyncio.wait_for(read_stream_async(), timeout=timeout_sec)
            exit_code = await loop.run_in_executor(None, process.wait)

            raw_output_str = "\n".join(full_output)
            db_run.raw_output = raw_output_str

            if exit_code != 0:
                analysis = OutputAnalyzer.analyze_output(raw_output_str, command_config.regex_rules)
                db_run.status = "Fail" if analysis["findings"] else "Error"
                findings = analysis["findings"] or [{"severity": "Warning", "message": f"Process exited with non-zero code {exit_code}."}]
                db_run.findings = json.dumps(findings)
            else:
                analysis = OutputAnalyzer.analyze_output(raw_output_str, command_config.regex_rules)
                db_run.status = analysis["status"]
                db_run.findings = json.dumps(analysis["findings"])

        except asyncio.TimeoutError:
            if process:
                process.kill()
            db_run.status = "Timeout"
            full_output.append("[TIMEOUT] Process killed after exceeding timeout limit.")
            db_run.raw_output = "\n".join(full_output)
            db_run.findings = json.dumps([{"severity": "High", "message": "Command execution timed out."}])
        except Exception as e:
            if process:
                process.kill()
            db_run.status = "Fail"
            full_output.append(f"[EXCEPTION] {repr(e)}")
            db_run.raw_output = "\n".join(full_output)
            db_run.findings = json.dumps([{"severity": "Critical", "message": f"Execution error: {str(e)}"}])
        finally:
            db_run.end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()

            if websocket:
                try:
                    await websocket.send_json({
                        "status": db_run.status,
                        "exit_code": process.returncode if process else -1
                    })
                    await websocket.close()
                except Exception:
                    pass

        return db_run
