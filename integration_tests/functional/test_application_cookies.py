"""
Test Overview:
Verifies BFF (Backend for Frontend) session management and device identification.
It ensures that session and device cookies are correctly issued with required 
security attributes (HttpOnly, Secure, SameSite) and that session continuity 
is maintained via Redis.

Required Domains:
- www.test.example.com: Basic reachability and device cookie verification.
- api.test.example.com: OIDC-protected route verification and session persistence.

Mock Servers:
- Port 9000 (httpserver.py): Unified Echo Server for all upstream requests.
"""
import pytest
import requests
import urllib3

# Suppress InsecureRequestWarning for private/self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = pytest.mark.functional

def parse_cookie(set_cookie_header, cookie_name):
    """
    Helper to extract specific cookie value and attributes from Set-Cookie header.
    """
    if not set_cookie_header or not cookie_name:
        return None
    
    parts = [p.strip() for p in set_cookie_header.split(';') if p.strip()]
    if not parts:
        return None
        
    first_part = parts[0].split('=', 1)
    if len(first_part) < 2 or first_part[0].strip() != cookie_name:
        return None
        
    value = first_part[1]
    attributes = {kv.split('=', 1)[0].strip().lower(): (kv.split('=', 1)[1].strip() if '=' in kv else True) 
                  for kv in parts[1:] if kv}
    return {"value": value, "attributes": attributes}

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_gateway_reachable(resolve_to_localhost):
    """
    Verify gateway reachability and basic name resolution.
    """
    url = "https://www.test.example.com:8443/robot.txt"
    try:
        r = requests.get(url, verify=False, timeout=2)
        assert r.status_code == 200, f"Gateway connected but returned {r.status_code}"
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Could not connect to Gateway at 127.0.0.1:8443. Is spngw running? Error: {e}")

@pytest.mark.parametrize("resolve_to_localhost", ["api.test.example.com"], indirect=True)
def test_session_cookie_issuance_on_protected_route(resolve_to_localhost):
    """
    Verify session cookie issuance with correct scope on protected routes.
    when accessing a path configured with RequireAuthentication.
    """
    url = "https://api.test.example.com:8443/dashboard"

    # verify=False: Allow private/self-signed certificates
    # The hostname in the URL ensures correct SNI and Host header
    # conftest.py's socket patch ensures it connects to 127.0.0.1
    r = requests.get(url, verify=False, timeout=5, allow_redirects=False)
    assert r.status_code == 302
    
    # 1. Verify cookie existence in the jar
    session_cookie = next((c for c in r.cookies if c.name.startswith("CHIPIN_SESSION_ID_")), None)
    assert session_cookie is not None, f"Session cookie missing. Found: {list(r.cookies.keys())}"

    # 2. Verify attributes from raw headers
    # r.raw.headers (urllib3 HTTPHeaderDict) supports getlist to avoid comma-separation issues
    raw_headers = r.raw.headers.getlist('Set-Cookie')
    raw_header = next((h for h in raw_headers if h.strip().startswith(session_cookie.name)), None)
    cookie_info = parse_cookie(raw_header, session_cookie.name)
    
    assert cookie_info is not None
    assert len(cookie_info["value"]) > 20  # Ensure it has sufficient length (Base64 encoded).
    
    # Attribute verification
    attrs = cookie_info["attributes"]
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert str(attrs.get("samesite")).lower() == "lax"
    assert attrs.get("path") == "/"
    assert "max-age" in attrs

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_device_cookie_issuance_and_attributes(resolve_to_localhost):
    """
    Verify that IssueDeviceCookie works for all requests and 
    issues a long-lived device context cookie.
    """
    url = "https://www.test.example.com:8443/"

    # verify=False: Allow private/self-signed certificates
    r = requests.get(url, verify=False, timeout=5)
    assert r.status_code == 200
    
    device_cookie = r.cookies.get("CHIPIN_DEVICE_CONTEXT", domain="www.test.example.com")
    assert device_cookie is not None

    # Verify device cookie attributes
    raw_headers = r.raw.headers.getlist('Set-Cookie')
    raw_header = next((h for h in raw_headers if h.strip().startswith("CHIPIN_DEVICE_CONTEXT")), None)
    cookie_info = parse_cookie(raw_header, "CHIPIN_DEVICE_CONTEXT")
    
    assert cookie_info is not None
    
    # Device cookie attribute verification
    attrs = cookie_info["attributes"]
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert str(attrs.get("samesite")).lower() == "strict"
    max_age = attrs.get("max-age")
    assert max_age and int(max_age) > 30000000  # 約1年(31536000秒)に近いことを確認

@pytest.mark.parametrize("resolve_to_localhost", ["api.test.example.com"], indirect=True)
def test_session_cookie_persistence(resolve_to_localhost):
    """
    Verify that an issued session ID is maintained in subsequent requests.
    """
    auth_url = "https://api.test.example.com:8443/dashboard"
    check_url = "https://api.test.example.com:8443/session-check"
    session = requests.Session()
    
    # 1. Obtain cookie on first access
    r1 = session.get(auth_url, verify=False, timeout=5, allow_redirects=False)
    session_cookie = next((c for c in session.cookies if c.name.startswith("CHIPIN_SESSION_ID_")), None)
    assert session_cookie is not None
    print(f"DEBUG: Obtained session cookie: {session_cookie.name}")

    # 2. Access again by sending the cookie.
    # Access a non-authenticated route that still uses the session scope.
    # If recognized, the gateway proxies to backend (200 OK) instead of initiating OIDC (302).
    r2 = session.get(check_url, verify=False, timeout=5, allow_redirects=False)
    
    assert r2.status_code == 200, f"Session failed. Expected 200 OK, but got {r2.status_code}"
