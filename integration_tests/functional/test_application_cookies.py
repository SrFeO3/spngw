import os
import pytest
import requests
import urllib3

# Disable warnings for self-signed SSL certificates in the test environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get TLS bind address from environment variables to determine the port
TLS_BIND_ADDR = os.getenv("APIGW_TLS_BIND_ADDRESS", "0.0.0.0:8443")
PORT = TLS_BIND_ADDR.split(":")[-1]

# Base URLs based on domains from conftest.py and the determined port
BASE_URL_WWW = f"https://www.test.example.com:{PORT}"
BASE_URL_API = f"https://api.test.example.com:{PORT}"
BFF_SCOPE = "TEST-SCOPE"


@pytest.fixture
def session():
    """requests.Session to maintain state (Cookies) across requests."""
    sess = requests.Session()
    sess.verify = False
    return sess


def get_set_cookie_header_by_name(response, name):
    """Get the Set-Cookie header value for a specific cookie name."""
    raw_headers = response.raw.headers.getlist("Set-Cookie")
    for header in raw_headers:
        if header.strip().startswith(f"{name}="):
            return header
    return None


def parse_cookie_attributes(set_cookie_header):
    """Parse Set-Cookie header attributes into a dictionary."""
    if not set_cookie_header:
        return {}
    parts = [p.strip() for p in set_cookie_header.split(";")]
    cookie_value = parts[0]
    name, value = cookie_value.split("=", 1)

    attrs = {"name": name, "value": value}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.lower().strip()] = v.strip()
        else:
            attrs[part.lower().strip()] = True
    return attrs


# --- 1.1 Normal Cases ---

def test_01_gateway_connectivity(session):
    """
    1.1 Gateway connectivity check: Verifies basic network connection and name resolution to the BFF.
    """
    url = f"{BASE_URL_WWW}/"
    response = session.get(url, allow_redirects=False)
    assert response.status_code == 200


def test_02_session_cookie_issuance_and_attributes(session):
    """
    1.1 Session cookie issuance and attributes: Verifies that an unauthenticated access to /dashboard 
    issues a session ID with HttpOnly, Secure, SameSite=Lax, and Path=/ attributes.
    """
    url = f"{BASE_URL_API}/dashboard"
    response = session.get(url, allow_redirects=False)

    cookie_name = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    assert cookie_name in response.cookies, f"{cookie_name} was not issued."
    
    header_val = get_set_cookie_header_by_name(response, cookie_name)
    assert header_val is not None
    
    attrs = parse_cookie_attributes(header_val)
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert attrs.get("samesite", "").lower() == "lax"
    assert attrs.get("path") == "/"


def test_03_device_cookie_issuance_and_attributes(session):
    """
    1.1 Device cookie issuance and attributes: Verifies that access to / issues a device cookie 
    with HttpOnly, Secure, SameSite=Strict, and a long-term (1 year) expiry.
    """
    url = f"{BASE_URL_WWW}/"
    response = session.get(url, allow_redirects=False)

    cookie_name = "CHIPIN_DEVICE_CONTEXT"
    assert cookie_name in response.cookies, f"{cookie_name} was not issued."
    
    header_val = get_set_cookie_header_by_name(response, cookie_name)
    assert header_val is not None

    attrs = parse_cookie_attributes(header_val)
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert attrs.get("samesite", "").lower() == "strict"
    assert attrs.get("path") == "/"

    max_age_str = attrs.get("max-age")
    assert max_age_str is not None
    max_age = int(max_age_str)
    assert 31500000 <= max_age <= 31600000


def test_04_session_continuity(session):
    """
    1.1 Session continuity: Verifies that cookie values remain unchanged during subsequent
    requests when both IDs are held.
    """
    session.get(f"{BASE_URL_WWW}/", allow_redirects=False)
    did_1 = session.cookies.get("CHIPIN_DEVICE_CONTEXT")
    assert did_1 is not None

    cookie_name_session = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    session.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)
    sid_1 = session.cookies.get(cookie_name_session)
    assert sid_1 is not None

    session.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)

    sid_2 = session.cookies.get(cookie_name_session)
    did_2 = session.cookies.get("CHIPIN_DEVICE_CONTEXT")

    assert sid_1 == sid_2
    assert did_1 == did_2


def test_05_device_id_continuity_on_session_clear(session):
    """
    1.1 Device ID continuity: Verifies that the device ID persists even when the session cookie 
    is cleared and a new session ID is issued.
    """
    cookie_name_session = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    cookie_name_device = "CHIPIN_DEVICE_CONTEXT"

    session.get(f"{BASE_URL_WWW}/", allow_redirects=False)
    session.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)

    did_1 = session.cookies.get(cookie_name_device)
    sid_1 = session.cookies.get(cookie_name_session)
    assert did_1 is not None
    assert sid_1 is not None

    session.cookies.set(cookie_name_session, None)

    session.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)
    did_2 = session.cookies.get(cookie_name_device)
    sid_2 = session.cookies.get(cookie_name_session)

    assert did_1 == did_2
    assert sid_2 is not None
    assert sid_1 != sid_2


def test_06_client_independence(session):
    """
    1.1 Client independence: Verifies that session IDs are unique across different clients.
    """
    cookie_name = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"

    session_a = requests.Session()
    session_a.verify = False
    session_a.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)
    sid_a = session_a.cookies.get(cookie_name)

    session_b = requests.Session()
    session_b.verify = False
    session_b.get(f"{BASE_URL_API}/dashboard", allow_redirects=False)
    sid_b = session_b.cookies.get(cookie_name)

    assert sid_a is not None
    assert sid_b is not None
    assert sid_a != sid_b


# --- 1.2 Negative Cases ---

def test_07_invalid_device_cookie_fallback(session):
    """
    1.2 Device cookie tampering resistance: Verifies that invalid/tampered device cookies 
    are handled safely by re-issuing a new valid cookie.
    """
    cookie_name_device = "CHIPIN_DEVICE_CONTEXT"
    malformed_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.invalidpayload.invalidsignature"
    session.cookies.set(cookie_name_device, malformed_jwt)

    response = session.get(f"{BASE_URL_WWW}/", allow_redirects=False)
    assert response.status_code == 200

    new_did = response.cookies.get(cookie_name_device)
    assert new_did is not None
    assert new_did != malformed_jwt


def test_08_invalid_format_session_cookie_fallback(session):
    """
    1.2 Malformed session ID: Verifies that malformed session IDs result in a safe fallback:
    issuing a new session and redirecting (302).
    """
    cookie_name_session = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    session.cookies.set(cookie_name_session, "short-and-invalid")

    url_auth = f"{BASE_URL_API}/dashboard"
    response = session.get(url_auth, allow_redirects=False)

    assert response.status_code == 302
    new_sid = response.cookies.get(cookie_name_session)
    assert new_sid is not None
    assert new_sid != "short-and-invalid"


def test_09_nonexistent_session_cookie_handling(session):
    """
    1.2 Non-existent/Expired session ID: Verifies that valid-format session IDs not present in Redis
    are treated as unauthenticated, triggering a redirect and a new cookie.
    """
    cookie_name_session = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    # Dummy session ID that is valid in format but does not exist in the store
    nonexistent_sid = "A" * 43
    session.cookies.set(cookie_name_session, nonexistent_sid)

    url_auth = f"{BASE_URL_API}/dashboard"
    response = session.get(url_auth, allow_redirects=False)
    
    assert response.status_code == 302
    new_sid = response.cookies.get(cookie_name_session)
    assert new_sid is not None
    assert new_sid != nonexistent_sid