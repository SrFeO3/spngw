import pytest
import requests

pytestmark = pytest.mark.functional

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_static_text_robot_txt(resolve_to_localhost):
    """
    Rule: match: "request.path.equals('/robot.txt')"
    Action: returnStaticText
    """
    url = "https://www.test.example.com:8443/robot.txt"
    r = requests.get(url, verify=False, timeout=5)
    assert r.status_code == 200
    assert "User-agent: *" in r.text
    assert "Disallow: /" in r.text

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_proxy_www_root(resolve_to_localhost):
    """
    Rule: match: "hostname.equals('www.test.example.com')"
    Action: proxy upstream: "http://127.0.0.1:9000"
    """
    url = "https://www.test.example.com:8443/"
    r = requests.get(url, verify=False, timeout=5)
    assert r.status_code == 200

@pytest.mark.parametrize("resolve_to_localhost", ["auth.test.example.com"], indirect=True)
def test_proxy_auth_host(resolve_to_localhost):
    """
    Rule: match: "hostname.equals('auth.test.example.com')"
    Action: proxy upstream: "http://127.0.0.1:9001"
    """
    url = "https://auth.test.example.com:8443/hello"
    r = requests.get(url, headers={"Host": "auth.test.example.com"}, verify=False, timeout=5)
    assert r.status_code == 200

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_proxy_api_path(resolve_to_localhost):
    """
    Rule: match: "request.path.starts_with('/api/')"
    Action: proxy upstream: "http://127.0.0.1:9002"
    """
    url = "https://www.test.example.com:8443/api/test"
    r = requests.get(url, verify=False, timeout=5)
    assert r.status_code == 200

@pytest.mark.parametrize("resolve_to_localhost", ["check.test.example.com"], indirect=True)
def test_proxy_check_host(resolve_to_localhost):
    """
    Rule: match: "hostname.equals('check.test.example.com')"
    Action: proxy upstream: "http://127.0.0.1:9003"
    """
    url = "https://check.test.example.com:8443/hello"
    r = requests.get(url, headers={"Host": "check.test.example.com"}, verify=False, timeout=5)
    assert r.status_code == 200

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_redirect_external(resolve_to_localhost):
    """
    Rule: match: "request.path.starts_with('/external/')"
    Action: redirect url: "https://ext.example.com/hello"
    """
    url = "https://www.test.example.com:8443/external/link"
    r = requests.get(url, verify=False, timeout=5, allow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"] == "https://ext.example.com/hello"

@pytest.mark.parametrize("resolve_to_localhost", ["www.test.example.com"], indirect=True)
def test_downstream_header(resolve_to_localhost):
    """
    Rule: match: "request.path.starts_with('/fruit/orange/')"
    Action: setDownstreamResponseHeader name: "X-Powered-By" value: "BFF-Proxy"
    """
    url = "https://www.test.example.com:8443/fruit/orange/juice"
    r = requests.get(url, verify=False, timeout=5)
    assert r.status_code == 200
    assert r.headers.get("X-Powered-By") == "BFF-Proxy"
