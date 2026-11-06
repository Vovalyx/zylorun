import sys
import time
import json
import urllib.request
import urllib.error
import urllib.parse

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

API_BASE = "http://127.0.0.1:8000"
FRONTEND_BASE = "http://localhost:5173"

MOBILE_USER_AGENTS = {
    "iPhone_Safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Android_Pixel": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.146 Mobile Safari/537.36"
}

def print_section(title):
    print(f"\n{'='*70}\n  {title}\n{'='*70}")

def assert_pass(condition, message):
    if not condition:
        print(f"  [FAIL] {message}")
        sys.exit(1)
    print(f"  [PASS] {message}")

def make_request(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    if data is not None and isinstance(data, dict):
        data_bytes = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif data is not None and isinstance(data, str):
        data_bytes = data.encode("utf-8")
    else:
        data_bytes = None

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            code = response.getcode()
            res_headers = dict(response.info())
            body = response.read().decode("utf-8", errors="ignore")
            try:
                json_data = json.loads(body)
            except Exception:
                json_data = None
            return code, json_data, body, res_headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        res_headers = dict(e.headers)
        try:
            json_data = json.loads(body)
        except Exception:
            json_data = None
        return e.code, json_data, body, res_headers
    except Exception as e:
        return 0, None, str(e), {}

def main():
    print("=" * 70)
    print("  EXECUTING MOBILE CONFIGURATION & LAN END-TO-END (E2E) SUITE")
    print("  Testing: Mobile Viewports, LAN IP CORS, Contact Flow & Admin Inbox")
    print("=" * 70)

    # Test 1: Verify Mobile Viewport Meta Tags in Frontend
    print_section("Test 1: Mobile Viewport & Theme Color HTML Assurance")
    code, _, html_content, _ = make_request(FRONTEND_BASE)
    assert_pass(code == 200, "Frontend serving index.html on port 5173")
    assert_pass('viewport-fit=cover' in html_content, "Viewport configured with 'viewport-fit=cover' for mobile displays")
    assert_pass('name="theme-color" content="#030712"' in html_content, "Mobile browser theme-color meta tag configured (#030712)")
    assert_pass('apple-mobile-web-app-capable' in html_content, "Apple iOS mobile web app capability enabled")

    # Test 2: Mobile LAN Origin CORS Verification
    print_section("Test 2: Mobile LAN IP CORS Origin Acceptance")
    test_origins = [
        "http://192.168.1.15:5173",
        "http://10.169.250.81:5173",
        "http://172.27.176.1:5173",
        "https://zylorun-five.vercel.app"
    ]
    for origin in test_origins:
        # Preflight OPTIONS request
        code, _, _, headers = make_request(
            f"{API_BASE}/contact",
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type"
            }
        )
        assert_pass(code == 200, f"CORS Preflight OPTIONS for origin '{origin}' returned HTTP 200")
        allow_origin = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
        assert_pass(allow_origin == origin, f"Access-Control-Allow-Origin correctly echoes '{origin}'")

    # Test 3: Simulated Mobile Inquiries via iPhone & Android Chrome
    print_section("Test 3: Mobile User Simulated Contact Inquiries")
    created_message_ids = []

    for device_name, ua in MOBILE_USER_AGENTS.items():
        payload = {
            "name": f"Mobile Tester ({device_name})",
            "email": f"{device_name.lower()}@vovalyx.in",
            "subject": f"Mobile Integration Query from {device_name}",
            "message": f"Autonomous verification inquiry initiated via {device_name} mobile browser."
        }
        code, json_data, _, _ = make_request(
            f"{API_BASE}/contact",
            method="POST",
            data=payload,
            headers={
                "User-Agent": ua,
                "Origin": "http://10.169.250.81:5173"
            }
        )
        assert_pass(code == 200, f"Contact submission from {device_name} returned HTTP 200 OK")
        assert_pass(json_data and json_data.get("status") == "success", f"Inquiry status confirms success for {device_name}")
        msg_id = json_data.get("message_id")
        assert_pass(bool(msg_id), f"Database generated contact inquiry ID: {msg_id}")
        created_message_ids.append(msg_id)

    # Test 4: Master Admin Contact Messages Inbox Verification
    print_section("Test 4: Admin Portal Inbox Telemetry & Message Retrieval")
    # Login as admin to get token
    login_data = f"username={urllib.parse.quote('admin')}&password={urllib.parse.quote('VovalyxAdmin2026!')}".encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}/auth/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        admin_auth = json.loads(resp.read().decode("utf-8"))
    
    admin_token = admin_auth.get("access_token")
    assert_pass(bool(admin_token), "Master Admin JWT token acquired for admin security center")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    code, messages_list, _, _ = make_request(
        f"{API_BASE}/admin/contact-messages",
        headers=admin_headers
    )
    assert_pass(code == 200, "Admin endpoint /admin/contact-messages returned HTTP 200")
    assert_pass(isinstance(messages_list, list), f"Retrieved {len(messages_list)} contact inquiries from admin portal")

    # Verify our mobile test messages are in the inbox
    inbox_ids = [m["id"] for m in messages_list]
    for mid in created_message_ids:
        assert_pass(mid in inbox_ids, f"Mobile inquiry ID #{mid} is present in Admin Security Center inbox")

    # Test 5: Admin Message Triage / Clean Deletion
    print_section("Test 5: Admin Inquiry Triage & Message Cleanup")
    for mid in created_message_ids:
        code, del_res, _, _ = make_request(
            f"{API_BASE}/admin/contact-messages/{mid}",
            method="DELETE",
            headers=admin_headers
        )
        assert_pass(code == 200, f"Deleted test mobile inquiry ID #{mid} (HTTP 200 OK)")

    print("\n" + "=" * 70)
    print("  MOBILE CONFIGURATION & LAN END-TO-END SUITE PASSED (100% 🟢)")
    print("  Local & Mobile Environment Verified Fully Functional!")
    print("=" * 70)

if __name__ == "__main__":
    main()
