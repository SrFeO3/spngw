import os
import pytest
import requests
import urllib3
from urllib.parse import urlparse, parse_qs

# Disable warnings for self-signed SSL certificates in the test environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get TLS bind address from environment variables to determine the port
TLS_BIND_ADDR = os.getenv("APIGW_TLS_BIND_ADDRESS", "0.0.0.0:8443")
PORT = TLS_BIND_ADDR.split(":")[-1]

BASE_URL_API = f"https://api.test.example.com:{PORT}"
BASE_URL_WWW = f"https://www.test.example.com:{PORT}"
BFF_SCOPE = "TEST-SCOPE"


@pytest.fixture
def session():
    """requests.Session to maintain state (Cookies) across tests."""
    sess = requests.Session()
    sess.verify = False
    return sess


# ==========================================
# 2.1 OIDC Success Cases
# ==========================================

def test_01_oidc_authorization_trigger(session):
    """
    OIDC Authorization Trigger:
    Verifies that unauthenticated access to /dashboard redirects to the OIDC provider.
    """
    url = f"{BASE_URL_API}/dashboard"
    response = session.get(url, allow_redirects=False)
    
    assert response.status_code == 302
    redirect_location = response.headers.get("Location")
    assert redirect_location is not None
    
    parsed_url = urlparse(redirect_location)
    assert parsed_url.netloc == "auth.test.example.com"
    assert parsed_url.path == "/authorize"
    
    params = parse_qs(parsed_url.query)
    assert params.get("response_type") == ["code"]
    assert params.get("client_id") == ["test-client"]
    assert params.get("redirect_uri") == ["api.test.example.com:8443/dashboard"]
    assert "state" in params
    assert "nonce" in params
    assert "code_challenge" in params
    assert params.get("code_challenge_method") == ["S256"]


def test_02_unauthenticated_api_me_intercept_redirect(session):
    """
    Unauthenticated User Info API Access:
    Verifies that unauthenticated access to /api/me redirects to the OIDC provider
    instead of returning JSON.
    """
    url = f"{BASE_URL_API}/api/me"
    response = session.get(url, allow_redirects=False)
    
    assert response.status_code == 302
    redirect_location = response.headers.get("Location")
    assert redirect_location is not None
    assert "auth.test.example.com/authorize" in redirect_location


# ==========================================
# 2.2 OIDC Negative Cases
# ==========================================

def test_03_oidc_callback_state_mismatch_fails(session):
    """
    Invalid Authentication Callback (CSRF protection):
    Verifies that a callback with a mismatched state triggers a redirect to the OIDC provider.
    """
    url_auth = f"{BASE_URL_API}/dashboard"
    session.get(url_auth, allow_redirects=False)
    
    callback_url = f"{BASE_URL_API}/dashboard?code=dummy_code_value&state=invalid_mismatched_state"
    response = session.get(callback_url, allow_redirects=False)
    
    assert response.status_code == 302
    redirect_location = response.headers.get("Location")
    assert redirect_location is not None
    assert "auth.test.example.com/authorize" in redirect_location


def test_04_oidc_callback_missing_state_in_session_fails(session):
    """
    Invalid Authentication Callback (No session):
    Verifies that a callback without a session triggers a redirect to the OIDC provider.
    """
    callback_url = f"{BASE_URL_API}/dashboard?code=dummy_code_value&state=some_random_state"
    response = session.get(callback_url, allow_redirects=False)
    
    assert response.status_code == 302
    redirect_location = response.headers.get("Location")
    assert redirect_location is not None
    assert "auth.test.example.com/authorize" in redirect_location


def test_05_oidc_callback_error_response_handling(session):
    """
    Invalid Authentication Callback (Provider error):
    Verifies that the BFF returns 401 Unauthorized when the OIDC provider returns
    an error code (e.g., access_denied).
    """
    url_auth = f"{BASE_URL_API}/dashboard"
    session.get(url_auth, allow_redirects=False)
    
    error_callback_url = f"{BASE_URL_API}/dashboard?error=access_denied&error_description=User+rejected+the+request"
    response = session.get(error_callback_url, allow_redirects=False)
    
    assert response.status_code == 401
    assert "access_denied" in response.text or "Authentication failed" in response.text


def test_06_unauthenticated_protected_route_with_fake_session(session):
    """
    Invalid or Expired Session on Protected Route:
    Verifies that access with an invalid session ID results in a redirect to the OIDC provider.
    """
    cookie_name_session = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    fake_session_id = "B" * 43
    session.cookies.set(cookie_name_session, fake_session_id)
    
    url = f"{BASE_URL_API}/dashboard"
    response = session.get(url, allow_redirects=False)
    
    assert response.status_code == 302
    redirect_location = response.headers.get("Location")
    assert redirect_location is not None
    assert "auth.test.example.com/authorize" in redirect_location


# ==========================================
# Security Isolation and Scope Design
# ==========================================

def test_07_scope_isolation_cookie_names(session):
    """
    Scope Isolation:
    Verifies that session cookies are scoped using the CHIPIN_SESSION_ID_{SCOPE} format.
    """
    url_test_scope = f"{BASE_URL_API}/dashboard"
    r_test = session.get(url_test_scope, allow_redirects=False)
    
    cookie_test = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    assert cookie_test in r_test.cookies
    assert "CHIPIN_SESSION_ID_OTHER-SCOPE" not in r_test.cookies


def test_08_path_isolation_and_no_scope_cookies(session):
    """
    Path Isolation:
    Verifies that routes without an auth scope do not issue session cookies,
    but still issue device cookies.
    """
    session_clean = requests.Session()
    session_clean.verify = False
    
    url_normal_proxy = f"{BASE_URL_API}/fruit/orange/test"
    response = session_clean.get(url_normal_proxy, allow_redirects=False)
    
    cookie_test = f"CHIPIN_SESSION_ID_{BFF_SCOPE}"
    assert cookie_test not in response.cookies
    assert "CHIPIN_DEVICE_CONTEXT" in response.cookies