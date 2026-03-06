#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple SPA Server (multithreaded) for integration tests.

This implementation uses a BFF (Backend for Frontend) pattern via spngw.
Contrast this with appserver_spa.py (Pure SPA).
"""

# BFF Configuration
# The BFF (spngw) handles OIDC.
# External BFF URL: https://www.test.example.com:8443
# This server runs on: http://localhost:7445 (Upstream for BFF)

PROTECTED_MOUNT_POINT = "/protected"

from datetime import datetime
from bottle import Bottle, request, response, ServerAdapter

# --- Boilerplate for multi-threaded server ---
from wsgiref.simple_server import make_server, WSGIRequestHandler, WSGIServer
from socketserver import ThreadingMixIn

class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True

class MultiThreadedServer(ServerAdapter):
    def run(self, handler):
        httpd = make_server(self.host, self.port, handler,
                            server_class=ThreadingWSGIServer,
                            handler_class=WSGIRequestHandler)
        httpd.serve_forever()

# --- Application ---

app = Bottle()

@app.get(PROTECTED_MOUNT_POINT + '/')
def index():
    """
    Main page. Serves the SPA.
    """

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.url}")
    print(f" > Host: {request.headers.get('Host')}")
    # In BFF mode, we expect the BFF to pass the session cookie (if configured to forward it)
    # or just handle auth. The app itself might not see the OIDC tokens.
    print(f" > Cookie: {request.headers.get('Cookie')}")

    response.content_type = 'text/html; charset=utf-8'
    return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>BFF SPA Test</title>
            <style>body {{ font-family: sans-serif; padding: 20px; }} .box {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}</style>
        </head>
        <body>
            <h1>BFF SPA Test Application</h1>
            <p>SPA accessing APIs via BFF (spngw). Authentication is handled by the BFF.</p>
            <p><strong>Note:</strong> No OIDC tokens are handled in the browser.</p>

            <div class="box">
                <h3>1. Authentication</h3>
                <p>Status: <strong id="auth-status" style="color: gray;">Checking...</strong></p>
                <p>User: <span id="username">-</span></p>
                <!--
                  Login: Navigate to a protected route.
                  spngw will intercept and redirect to OIDC if not authenticated.
                -->
                <button onclick="window.location.href='{PROTECTED_MOUNT_POINT}/login'">Login (via BFF)</button>
                <!--
                  Logout: Navigate to logout endpoint.
                -->
                <button onclick="window.location.href='{PROTECTED_MOUNT_POINT}/logout'">Logout</button>
            </div>

            <div class="box">
                <h3>2. API Call</h3>
                <p>Target: <code>{PROTECTED_MOUNT_POINT}/api/add/1/2</code> (Proxied by BFF)</p>
                <button onclick="callApi()">Call API (1 + 2)</button>
                <p>Result: <span id="api-result" style="font-weight: bold;">...</span></p>
            </div>

            <script>
                // Check authentication status by calling the BFF's user info endpoint.
                // spngw provides /api/me for this purpose.
                async function checkAuth() {{
                    try {{
                        const res = await fetch('{PROTECTED_MOUNT_POINT}/api/me');
                        if (res.ok) {{
                            const data = await res.json();
                            document.getElementById('auth-status').textContent = "Logged In";
                            document.getElementById('auth-status').style.color = "green";
                            document.getElementById('username').textContent = data.name || "Unknown";
                        }} else {{
                            document.getElementById('auth-status').textContent = "Not Logged In";
                            document.getElementById('auth-status').style.color = "red";
                        }}
                    }} catch (e) {{
                        console.error(e);
                        document.getElementById('auth-status').textContent = "Error checking auth";
                    }}
                }}

                function callApi() {{
                    // No Authorization header needed! The BFF attaches it.
                    // We call the API relative to the BFF root.
                    fetch('{PROTECTED_MOUNT_POINT}/api/add/1/2')
                        .then(res => res.ok ? res.json() : {{ error: res.status + " " + res.statusText }})
                        .then(data => document.getElementById('api-result').textContent = data.result || data.error)
                        .catch(err => document.getElementById('api-result').textContent = "Error: " + err);
                }}

                // Check auth on page load
                checkAuth();
            </script>
        </body>
        </html>
        """

@app.route(PROTECTED_MOUNT_POINT + '/login')
def login():
    """
    Dummy login route.
    This route should be configured in spngw to RequireAuthentication.
    When accessed, spngw triggers OIDC login.
    After login, spngw passes the request here, and we redirect to home.
    """
    response.status = 302
    response.set_header('Location', PROTECTED_MOUNT_POINT + '/')
    return "Redirecting..."

@app.route(PROTECTED_MOUNT_POINT + '/logout')
def logout():
    """
    Dummy logout route.
    In a real scenario, this would clear the session cookie.
    """
    response.status = 302
    response.set_header('Location', PROTECTED_MOUNT_POINT + '/')
    return "Redirecting..."

# --- Main execution ---

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple App Server for BFF tests")
    parser.add_argument("--port", type=int, default=7445,
                        help="Port (default: 7445)")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")

    args = parser.parse_args()
    print(f"Serving on {args.host}:{args.port}")
    app.run(server=MultiThreadedServer, host=args.host, port=args.port)
