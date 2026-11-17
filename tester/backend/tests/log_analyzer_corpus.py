"""Ground-truth corpus for the log & code analyzer.

Every case states exactly which findings a correct analyzer must report
(rule id, severity and, where it matters, the 1-based line number) and the
overall status. Any Critical or Warning finding that is not listed is a false
positive; any listed finding that is missing is a false negative.

Secret-shaped strings are assembled at runtime so this file never contains a
literal that secret scanners (or GitHub push protection) would treat as a key.
"""

# Synthetic credentials, built from pieces. None of these are real.
FAKE_GITHUB_TOKEN = "ghp_" + "Q7xR2pLm9TwZ4nBv" + "K8cD1fGh3JkL5mNp" + "Rs6T"
FAKE_AWS_KEY = "AKIA" + "Q7XR2PLM9TWZ4NBV"
DOC_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"          # AWS's own documentation example
FAKE_DB_PASSWORD = "Xk9" + "pQ2vL7mZt4"

CASES = [
    # ------------------------------------------------------------------ logs
    {
        "id": "render_traceback",
        "kind": "log",
        "text": """2026-11-17T04:05:22.272451031Z ==> Exited with status 1
2026-11-17T04:05:29.229640548Z Traceback (most recent call last):
2026-11-17T04:05:29.229661668Z   File "/usr/local/bin/uvicorn", line 8, in <module>
2026-11-17T04:05:29.229840542Z     sys.exit(main())
2026-11-17T04:05:29.232278742Z   File "/app/app/main.py", line 5, in <module>
2026-11-17T04:05:29.232380375Z     from app.api.routes import (
2026-11-17T04:05:29.232698833Z   File "/app/app/scanners/secrets.py", line 340, in <module>
2026-11-17T04:05:29.232897268Z     def scan_content_for_secrets(raw_text: str, filename: str = "snippet.txt") -> List[Dict[str, Any]]:
2026-11-17T04:05:29.233068792Z NameError: name 'Dict' is not defined. Did you mean: 'dict'?""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-PROCESS-EXIT", "severity": "Critical", "line": 1},
            {"rule": "LOG-PY-EXCEPTION", "severity": "Critical", "line": 9,
             "contains": ["NameError", "secrets.py", "340"]},
        ],
    },
    {
        "id": "render_runtime_error",
        "kind": "log",
        "text": """2026-11-17T06:39:55.265435366Z   File "/app/app/config.py", line 166, in <module>
2026-11-17T06:39:55.265491361Z     validate_security_settings(settings)
2026-11-17T06:39:55.265502992Z   File "/app/app/config.py", line 129, in validate_security_settings
2026-11-17T06:39:55.265633942Z     raise RuntimeError(
2026-11-17T06:39:55.265719209Z RuntimeError: Refusing to start in production: DATABASE_URL is not set.
2026-11-17T06:40:11.812572631Z ==> Exited with status 1""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-PY-EXCEPTION", "severity": "Critical", "line": 5,
             "contains": ["RuntimeError", "DATABASE_URL", "config.py", "129"]},
            {"rule": "LOG-PROCESS-EXIT", "severity": "Critical", "line": 6},
        ],
    },
    {
        "id": "browser_console",
        "kind": "log",
        "text": """Failed to load resource: net::ERR_NETWORK_CHANGED   zylorun.onrender.com/auth/login:1
index-BZuKwZto.js:4  POST https://zylorun.onrender.com/auth/login 401 (Unauthorized)
index-BZuKwZto.js:4  POST https://zylorun.onrender.com/auth/login 401 (Unauthorized)""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-NETWORK", "severity": "Critical", "line": 1},
            {"rule": "LOG-HTTP-AUTH", "severity": "Warning", "line": 2, "count": 2,
             "contains": ["401", "/auth/login"]},
        ],
    },
    {
        "id": "npm_build_failure",
        "kind": "log",
        "text": """> frontend@0.0.0 build
> tsc -b && vite build

src/pages/Admin.tsx(12,5): error TS2322: Type 'string' is not assignable to type 'number'.
npm ERR! code ELIFECYCLE
npm ERR! errno 2
npm ERR! frontend@0.0.0 build: `tsc -b && vite build`
npm ERR! Exit status 2""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-BUILD-ERROR", "severity": "Critical", "line": 4,
             "contains": ["TS2322", "Admin.tsx"]},
            {"rule": "LOG-BUILD-ERROR", "severity": "Critical", "line": 5, "contains": ["ELIFECYCLE"]},
        ],
    },
    {
        "id": "node_crash",
        "kind": "log",
        "text": """Server listening on port 3000
TypeError: Cannot read properties of undefined (reading 'map')
    at Dashboard (/app/src/pages/Dashboard.js:42:17)
    at renderWithHooks (/app/node_modules/react-dom/cjs/react-dom.development.js:14985:18)
    at processTicksAndRejections (node:internal/process/task_queues:95:5)""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-JS-EXCEPTION", "severity": "Critical", "line": 2,
             "contains": ["TypeError", "Dashboard.js", "42"]},
        ],
    },
    {
        "id": "pytest_failure",
        "kind": "log",
        "text": """============================= test session starts ==============================
collected 114 items

tests/test_auth.py F..                                                   [  3%]
FAILED tests/test_auth.py::test_login - AssertionError: assert 401 == 200
========================= 1 failed, 113 passed in 3.21s =========================""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-TEST-FAILURE", "severity": "Critical", "line": 5,
             "contains": ["test_login", "assert 401 == 200"]},
        ],
    },
    {
        "id": "access_log_errors_and_attacks",
        "kind": "log",
        "text": """10.0.0.7 - - [17/Nov/2026:10:01:02 +0530] "GET /health HTTP/1.1" 200 54 "-" "curl/8.4"
10.0.0.7 - - [17/Nov/2026:10:01:05 +0530] "POST /api/orders HTTP/1.1" 500 120 "-" "Mozilla/5.0"
10.0.0.7 - - [17/Nov/2026:10:01:09 +0530] "POST /api/orders HTTP/1.1" 500 120 "-" "Mozilla/5.0"
203.0.113.9 - - [17/Nov/2026:10:02:00 +0530] "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 812 "-" "sqlmap/1.7"
203.0.113.9 - - [17/Nov/2026:10:02:03 +0530] "GET /static/../../etc/passwd HTTP/1.1" 404 0 "-" "curl/8.4"
INFO:     127.0.0.1:51234 - "GET /api/v1/health HTTP/1.1" 200 OK""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-HTTP-5XX", "severity": "Critical", "line": 2, "count": 2,
             "contains": ["500", "/api/orders"]},
            {"rule": "LOG-ATTACK-PAYLOAD", "severity": "Critical", "line": 4, "contains": ["SQL injection"]},
            {"rule": "LOG-ATTACK-PAYLOAD", "severity": "Critical", "line": 5, "contains": ["Path traversal"]},
        ],
    },
    {
        "id": "ssh_brute_force",
        "kind": "log",
        "text": "\n".join(
            f"Nov 17 10:0{i}:1{i} web sshd[811{i}]: Failed password for admin from 198.51.100.23 port 5{i}211 ssh2"
            for i in range(6)
        ) + "\nNov 17 10:07:00 web sshd[8200]: Accepted publickey for deploy from 10.0.0.2 port 50000 ssh2",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-BRUTE-FORCE", "severity": "Critical", "line": 1, "contains": ["198.51.100.23", "6"]},
        ],
    },
    {
        "id": "java_exception",
        "kind": "log",
        "text": """2026-11-17 10:00:00.123  INFO 1 --- [main] com.acme.App : Starting App
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "String.length()" because "name" is null
\tat com.acme.service.UserService.validate(UserService.java:57)
\tat com.acme.App.main(App.java:14)""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-JAVA-EXCEPTION", "severity": "Critical", "line": 2,
             "contains": ["NullPointerException", "UserService.java", "57"]},
        ],
    },
    {
        "id": "go_panic",
        "kind": "log",
        "text": """panic: runtime error: index out of range [3] with length 3

goroutine 1 [running]:
main.handler(...)
\t/srv/app/main.go:27 +0x1d
exit status 2""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-GO-PANIC", "severity": "Critical", "line": 1, "contains": ["index out of range", "main.go", "27"]},
            {"rule": "LOG-PROCESS-EXIT", "severity": "Critical", "line": 6},
        ],
    },
    {
        "id": "resource_failures",
        "kind": "log",
        "text": """<--- Last few GCs --->
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
psycopg2.OperationalError: could not connect to server: Connection refused
Error: EACCES: permission denied, open '/var/log/app.log'
OSError: [Errno 28] No space left on device""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-OOM", "severity": "Critical", "line": 2},
            {"rule": "LOG-NETWORK", "severity": "Critical", "line": 3, "contains": ["Connection refused"]},
            {"rule": "LOG-PERMISSION", "severity": "Critical", "line": 4},
            {"rule": "LOG-DISK", "severity": "Critical", "line": 5},
        ],
    },
    {
        "id": "leveled_app_log",
        "kind": "log",
        "text": """2026-11-17 10:00:00,001 INFO  app.server: Started on :8000
2026-11-17 10:00:05,442 WARNING app.cache: Redis latency above 200ms
2026-11-17 10:00:09,013 ERROR app.payments: Charge failed for order 1182: card_declined
2026-11-17 10:00:12,500 CRITICAL app.db: Primary database unreachable, switching to replica
{"time":"2026-11-17T10:00:13Z","level":"error","msg":"webhook delivery failed","status":502}""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-LEVEL-WARNING", "severity": "Warning", "line": 2},
            {"rule": "LOG-LEVEL-ERROR", "severity": "Critical", "line": 3, "contains": ["Charge failed"]},
            {"rule": "LOG-LEVEL-FATAL", "severity": "Critical", "line": 4},
            {"rule": "LOG-LEVEL-ERROR", "severity": "Critical", "line": 5, "contains": ["webhook delivery failed"]},
        ],
    },
    {
        "id": "ui_sample_build_log",
        "kind": "log",
        "text": """[INFO] --- maven-compiler-plugin:3.8.1:compile (default-compile) @ payment-service ---
[WARNING] /src/main/java/SecurityConfig.java:[42,12] deprecated API used: configure(HttpSecurity http)
[WARNING] Found outdated dependency: com.fasterxml.jackson.core:jackson-databind:2.9.10 (CVE-2020-36179 - Critical)
[CRITICAL] Security Scan Failed: Found hardcoded Bearer token in application.properties line 18
[ERROR] Static analysis: Insecure direct object reference (IDOR) detected in /controllers/OrderController.java
[INFO] Compilation finished with 1 error and 2 warnings.""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-LEVEL-WARNING", "severity": "Warning", "line": 2},
            {"rule": "LOG-LEVEL-WARNING", "severity": "Warning", "line": 3},
            {"rule": "LOG-LEVEL-FATAL", "severity": "Critical", "line": 4},
            {"rule": "LOG-LEVEL-ERROR", "severity": "Critical", "line": 5},
        ],
    },
    {
        "id": "ui_sample_auth_attack_log",
        "kind": "log",
        "text": """2026-10-16 11:42:01 [WARNING] [AuthService] Failed login attempt for user 'admin' from IP 192.168.1.104
2026-10-16 11:42:02 [WARNING] [AuthService] Rapid password brute-force detected from 192.168.1.104 (5 failed attempts / 3 sec)
2026-10-16 11:42:05 [CRITICAL] [WAF] SQL injection payload detected in query parameter 'username': "' OR '1'='1' --"
2026-10-16 11:42:07 [CRITICAL] [Perimeter] Malicious token leak attempt blocked for /api/v1/internal/secrets""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-LEVEL-WARNING", "severity": "Warning", "line": 1},
            {"rule": "LOG-LEVEL-WARNING", "severity": "Warning", "line": 2},
            {"rule": "LOG-LEVEL-FATAL", "severity": "Critical", "line": 3},
            {"rule": "LOG-LEVEL-FATAL", "severity": "Critical", "line": 4},
        ],
    },
    # ----------------------------------------------------- clean logs (no findings)
    {
        "id": "healthy_log",
        "kind": "log",
        "text": """2026-11-17 10:00:00,001 INFO  app.server: Started on :8000
2026-11-17 10:00:01,002 INFO  app.db: Connected (pool=5, errors=0)
INFO:     127.0.0.1:51234 - "GET /health HTTP/1.1" 200 OK
vite v8.3.0 building for production...
✓ 1873 modules transformed.
✓ built in 11.43s
Found 0 errors and 0 warnings.
error_count=0 retries=0
Compiled successfully. No errors.""",
        "expect_status": "Pass",
        "expect": [],
    },
    {
        "id": "prose_text",
        "kind": "log",
        "text": """Release notes: Select 3 items from the cart + proceed to checkout.
Users can now reset a password from the login page; the error message is clearer.
This release removes the token from the URL.""",
        "expect_status": "Pass",
        "expect": [],
    },
    # -------------------------------------------------------- vulnerable code
    {
        "id": "ui_sample_vulnerable_js",
        "kind": "code",
        "file_name": "vulnerable_auth_handler.js",
        "text": f"""// Vulnerable Authentication & User Lookup Module
const express = require('express');
const app = express();

const AWS_SECRET_KEY = "{DOC_AWS_KEY}";
const JWT_PRIVATE_KEY = "s3cr3t-Unrotated-jwt-K3y-9f8e7d";

app.post('/api/user/query', async (req, res) => {{
  const userId = req.body.id;
  // Flaw 1: Raw SQL Injection Concatenation
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND active = 1";
  const result = await db.query(query);

  // Flaw 2: Reflected Cross-Site Scripting (XSS)
  document.getElementById('profile').innerHTML = req.body.profileHtml;

  // Flaw 3: Dangerous Remote Code Evaluation
  const evaluated = eval(req.body.expression);

  res.json({{ status: 'ok', data: result }});
}});""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "SEC-SECRET-TOKEN", "severity": "Info", "line": 5, "contains": ["documentation example"]},
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 6},
            {"rule": "SEC-SQLI", "severity": "Critical", "line": 11},
            {"rule": "SEC-XSS", "severity": "Critical", "line": 15},
            {"rule": "SEC-CODE-EVAL", "severity": "Critical", "line": 18},
        ],
    },
    {
        "id": "vulnerable_python",
        "kind": "code",
        "file_name": "app/views.py",
        "text": f"""import os, pickle, subprocess, yaml, hashlib, requests
from flask import request

DEBUG = True
GITHUB_TOKEN = "{FAKE_GITHUB_TOKEN}"
DATABASE_URL = "postgresql://app:{FAKE_DB_PASSWORD}@db.internal:5432/prod"

def find_user(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{{name}}'")

def ping(host):
    os.system("ping -c 1 " + request.args["host"])

def load_profile():
    return pickle.loads(request.data)

def run_report(path):
    subprocess.run("tar czf out.tgz " + path, shell=True)

def read_config(text):
    return yaml.load(text)

def fetch(url):
    return requests.get(url, verify=False)

def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()

def download():
    return open("/srv/files/" + request.args["name"]).read()""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "CFG-DEBUG-ON", "severity": "Warning", "line": 4},
            {"rule": "SEC-SECRET-TOKEN", "severity": "Critical", "line": 5, "contains": ["GitHub"]},
            {"rule": "SEC-SECRET-URL", "severity": "Critical", "line": 6},
            {"rule": "SEC-SQLI", "severity": "Critical", "line": 9},
            {"rule": "SEC-CMDI", "severity": "Critical", "line": 12},
            {"rule": "SEC-DESERIALIZE", "severity": "Critical", "line": 15},
            {"rule": "SEC-CMDI", "severity": "Critical", "line": 18},
            {"rule": "SEC-DESERIALIZE", "severity": "Warning", "line": 21},
            {"rule": "SEC-TLS-VERIFY-OFF", "severity": "Warning", "line": 24},
            {"rule": "SEC-WEAK-HASH", "severity": "Warning", "line": 27},
            {"rule": "SEC-PATH-TRAVERSAL", "severity": "Critical", "line": 30},
        ],
    },
    {
        "id": "secrets_in_config_file",
        "kind": "code",
        "file_name": ".env",
        "text": f"""# local settings
AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}
SMTP_PASSWORD={FAKE_DB_PASSWORD}
SECRET_KEY=
API_BASE_URL=https://api.example.com""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "SEC-SECRET-TOKEN", "severity": "Critical", "line": 2, "contains": ["AWS"]},
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 3},
        ],
    },
    # ----------------------------------------- real tool output captured during testing
    {
        "id": "real_node_missing_module",
        "kind": "log",
        "text": """node:internal/modules/cjs/loader:1459
  throw err;
  ^

Error: Cannot find module 'missing-module-xyz-123'
Require stack:
- /srv/app/[eval]
    at Module._resolveFilename (node:internal/modules/cjs/loader:1456:15)
    at Module._load (node:internal/modules/cjs/loader:1242:25)
    at require (node:internal/modules/helpers:152:16)
    at [eval]:1:1
    at runScriptInThisContext (node:internal/vm:219:10)

Node.js v24.14.1""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-JS-EXCEPTION", "severity": "Critical", "line": 5, "contains": ["Cannot find module", "[eval]:1"]},
        ],
    },
    {
        "id": "real_npm_script_failure_message",
        "kind": "log",
        "text": """
> x@1.0.0 build
> node -e "console.error(\\"bundle failed\\"); process.exit(2)"

bundle failed""",
        "expect_status": "Warning",
        "expect": [
            {"rule": "LOG-FAILURE-MESSAGE", "severity": "Warning", "line": 5},
        ],
    },
    {
        "id": "real_git_permission_warnings",
        "kind": "log",
        "text": "\n".join(
            f"warning: could not open directory '{d}/': Permission denied"
            for d in ("Application Data", "Cookies", "Documents/My Music", "Local Settings", "NetHood")
        ) + "\nOn branch main\n\nNo commits yet\n\nnothing added to commit but untracked files present (use \"git add\" to track)",
        "expect_status": "Warning",
        "expect": [
            {"rule": "LOG-PERMISSION", "severity": "Warning", "line": 1, "count": 5},
        ],
    },
    {
        "id": "real_pip_not_found",
        "kind": "log",
        "text": """ERROR: Could not find a version that satisfies the requirement nonexistent-package-xyz-98765 (from versions: none)
ERROR: No matching distribution found for nonexistent-package-xyz-98765""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "LOG-LEVEL-ERROR", "severity": "Critical", "line": 1},
            {"rule": "LOG-LEVEL-ERROR", "severity": "Critical", "line": 2},
        ],
    },
    {
        "id": "git_history_is_not_an_error_log",
        "kind": "log",
        "text": """commit 12ac317d8e1b2c3a4f5e6d7c8b9a0f1e2d3c4b5a
Author: Dev <dev@example.com>
Date:   Tue Nov 17 11:26:00 2026 +0530

    fix(frontend): retry sign-in on network failure and show a clear connection message

    A request that never reached the API (for example net::ERR_NETWORK_CHANGED) was
    reported as 'Sign in failed', and the server could not be reached.

 tester/frontend/src/config.ts | 30 +++++++++++++++++++++++-------
 1 file changed, 23 insertions(+), 7 deletions(-)""",
        "expect_status": "Pass",
        "expect": [],
    },
    {
        "id": "hardcoded_credentials_patterns",
        "kind": "code",
        "file_name": "app/routes/admin.py",
        "text": f"""import os
valid_master_passes = ("{FAKE_DB_PASSWORD}", "AdminPass9!x")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "{FAKE_DB_PASSWORD}-fallback")
admin.hashed_password = get_password_hash("{FAKE_DB_PASSWORD}")
if verify_password("Pq7-{FAKE_DB_PASSWORD}", user.hashed_password):
    pass
isSecret = ['aws_secret', 'private_key', 'secret_key']
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
API_KEY = os.getenv("OPENAI_API_KEY", "")""",
        "expect_status": "Fail",
        "expect": [
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 2},
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 3, "contains": ["fallback"]},
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 4},
            {"rule": "SEC-SECRET-ASSIGN", "severity": "Critical", "line": 5},
        ],
    },
    {
        "id": "example_env_file_is_informational",
        "kind": "code",
        "file_name": "backend/.env.example",
        "text": f"""SECRET_KEY=""
# DATABASE_URL=postgresql+asyncpg://app_user:{FAKE_DB_PASSWORD}@db:5432/app
ADMIN_PASSWORD=""
GEMINI_API_KEY=your_gemini_api_key_here""",
        "expect_status": "Pass",
        "expect": [
            {"rule": "SEC-SECRET-URL", "severity": "Info", "line": 2},
        ],
    },
    # ------------------------------------------------- safe code (no findings)
    {
        "id": "safe_python",
        "kind": "code",
        "file_name": "app/repo.py",
        "text": """import os, subprocess, yaml
from sqlalchemy import select

SECRET_KEY = os.getenv("SECRET_KEY")
API_TOKEN = os.environ["API_TOKEN"]
PASSWORD_MIN_LENGTH = 8
DEBUG = os.getenv("DEBUG") == "1"

def find_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))

def find_user_orm(session, uid):
    return session.execute(select(User).where(User.id == uid)).scalar_one()

def status():
    return subprocess.run(["git", "status"], check=True, capture_output=True)

def read_config(text):
    return yaml.safe_load(text)

def log_failure(logger):
    logger.error("Payment failed")  # an error message in code is not an error in the code""",
        "expect_status": "Pass",
        "expect": [],
    },
    {
        "id": "safe_tsx",
        "kind": "code",
        "file_name": "src/components/Profile.tsx",
        "text": """import DOMPurify from 'dompurify';
import { useState } from 'react';

const apiKey = import.meta.env.VITE_API_KEY;
const token = localStorage.getItem('access_token');

export function Profile({ html, input }: { html: string; input: string }) {
  const [password, setPassword] = useState('');
  const match = /^[a-z]+$/.exec(input);
  const parts = pattern.exec(input);
  return (
    <form>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
      <p className="text-red-500">{match ? 'ok' : 'error'}</p>
    </form>
  );
}""",
        "expect_status": "Pass",
        "expect": [],
    },
]
