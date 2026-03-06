#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple SPA Server (multithreaded) for integration tests.

This implementation uses a pure SPA without a BFF.
"""

# OIDC Configuration
OIDC_ISSUER_URL = "https://xxx/"
OIDC_AUTHORIZATION_ENDPOINT = "https://xxx/authorize"
OIDC_CLIENT_ID = "xxx"
OIDC_REDIRECT_URI = "https://xxx/oidc/callback"
OIDC_AUDIENCE = "https://xxx:8443" # audience is an Auth0-specific dialect.
# Note on OIDC Provider differences:
# - Google OIDC: Access Token is opaque (Access Tokens issued for Google APIs are often opaque strings, not JWTs. Only ID Tokens are JWT.)
# - Auth0: Uses audience instead of resource (OAuth2 RFC 8707 defines the resource parameter; Auth0 uses audience parameter instead, but the resulting JWT aud claim is correct.)
# - Logto: Access Token may be opaque or JWT (Depending on configuration, Logto may issue JWT or opaque Access Tokens; behavior is not fully predictable.)

# Backend API Configuration
API_BASE_URL = "https://procyon.test.example.com:8443"

import json
import time
import threading
import re
import hashlib
import base64
from datetime import datetime
import requests
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

@app.get('/')
def index():
    """
    Main page. Serves the SPA.
    """

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.url}")
    print(f" > Host: {request.headers.get('Host')}")
    print(f" > Cookie: {request.headers.get('Cookie')}")

    response.content_type = 'text/html; charset=utf-8'
    return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Pure SPA Test(Non-BFF)</title>
            <style>body {{ font-family: sans-serif; padding: 20px; }} .box {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}</style>
        </head>
        <body>
            <h1>Pure SPA Test Application (Non-BFF)</h1>
            <p>Single Page Application accessing the API directly (CORS).</p>

            <div class="box">
                <h3>1. Authentication</h3>
                <p>Status: <strong id="auth-status" style="color: red;">Not Logged In</strong></p>
                <button onclick="loginWithOidc()">Login with OIDC</button>
                <button onclick="logout()">Logout</button>
            </div>

            <div class="box">
                <h3>2. API Call</h3>
                <p>Target: <code>{API_BASE_URL}/api/add/1/2</code></p>
                <button onclick="callApi()">Call API (1 + 2)</button>
                <p>Result: <span id="api-result" style="font-weight: bold;">...</span></p>
            </div>

            <script>
                let accessToken = null;

                // Generate random code verifier
                function generateCodeVerifier() {{
                    const randomBytes = new Uint8Array(32);
                    window.crypto.getRandomValues(randomBytes);
                    return btoa(String.fromCharCode.apply(null, randomBytes))
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=/g, '');
                }}

                // Compute code challenge
                async function generateCodeChallenge(verifier) {{
                    const encoder = new TextEncoder();
                    const data = encoder.encode(verifier);
                    const digest = await window.crypto.subtle.digest('SHA-256', data);
                    return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=/g, '');
                }}

                async function loginWithOidc() {{
                    const codeVerifier = generateCodeVerifier();
                    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
                    const codeChallenge = await generateCodeChallenge(codeVerifier);

                    const nonce = "test_nonce_" + Math.random().toString(36).substring(7);
                    sessionStorage.setItem('oidc_nonce', nonce);

                    const state = "test_state_" + Math.random().toString(36).substring(7);
                    sessionStorage.setItem('oidc_state', state);

                    console.log("--- OIDC Login Start ---");
                    console.log("Code Verifier:", codeVerifier);
                    console.log("Code Challenge:", codeChallenge);
                    console.log("Nonce:", nonce);
                    console.log("State:", state);

                    // Redirect to OIDC Provider
                    const authEndpoint = "{OIDC_AUTHORIZATION_ENDPOINT}";
                    const params = new URLSearchParams({{
                        client_id: "{OIDC_CLIENT_ID}",
                        redirect_uri: "{OIDC_REDIRECT_URI}",
                        response_type: "code",
                        scope: "openid offline_access",
                        state: state,
                        nonce: nonce,
                        code_challenge: codeChallenge,
                        code_challenge_method: 'S256',
                        audience: "{OIDC_AUDIENCE}", // Request JWT for this API
                    }});
                    window.location.href = `${{authEndpoint}}?${{params.toString()}}`;
                }}

                function logout() {{
                    accessToken = null;
                    document.getElementById('auth-status').textContent = "Not Logged In";
                    document.getElementById('auth-status').style.color = "red";
                    document.getElementById('api-result').textContent = "...";
                }}

                function callApi() {{
                    const headers = accessToken ? {{ 'Authorization': 'Bearer ' + accessToken }} : {{}};
                    fetch('{API_BASE_URL}/api/add/1/2', {{ headers: headers }})
                        .then(res => res.ok ? res.json() : {{ error: res.status + " " + res.statusText }})
                        .then(data => document.getElementById('api-result').textContent = data.result || data.error)
                        .catch(err => document.getElementById('api-result').textContent = "Error: " + err);
                }}
            </script>
        </body>
        </html>
        """

@app.route('/oidc/callback')
def oidc_callback():
    """
    Handle OIDC callback for SPA mode.
    Handles the 'After Login' state via JS router.
    """
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.url}")
    code = request.query.get('code')
    state = request.query.get('state')
    print(f" > Code: {code}")
    print(f" > State: {state}")

    # Server serves the page; JS handles token exchange.
    token_endpoint = f"{OIDC_ISSUER_URL.rstrip('/')}/oauth/token"
    userinfo_endpoint = f"{OIDC_ISSUER_URL.rstrip('/')}/userinfo"

    # Render the SPA page in 'Logged In' state
    response.content_type = 'text/html; charset=utf-8'
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Pure SPA Test (Callback)</title>
        <style>body {{ font-family: sans-serif; padding: 20px; }} .box {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}</style>
    </head>
    <body>
        <h1>Pure SPA Test Application (Callback Received)</h1>
        <p>OIDC Callback handled by App Server (Non-BFF Mode).</p>

        <div class="box">
            <h3>1. Authentication</h3>
            <p>Status: <strong style="color: green;">Logged In</strong></p>
            <p>Code: <code>{code}</code></p>
            <p>State (Returned): <code>{state}</code></p>
            <p>State (Stored): <code id="state-display">...</code></p>
            <p>Nonce: <code id="nonce-display">...</code></p>
            <p>Code Verifier: <code id="verifier-display">...</code></p>
            <p>Access Token: <code id="access-token-display" style="word-break: break-all;">Exchanging code...</code></p>
            <button onclick="window.location.href='/'">Logout (Reset)</button>
        </div>

        <div class="box">
            <h3>2. User Info</h3>
            <pre id="userinfo-display" style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">Waiting for token...</pre>
        </div>

        <div class="box">
            <h3>3. API Call</h3>
            <p>Target: <code>{API_BASE_URL}/api/add/1/2</code></p>
            <button onclick="callApi()">Call API (1 + 2)</button>
            <p>Result: <span id="api-result" style="font-weight: bold;">...</span></p>
        </div>

        <script>
            // Script runs on callback page.
            const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
            const nonce = sessionStorage.getItem('oidc_nonce');
            const state = sessionStorage.getItem('oidc_state');

            document.getElementById('verifier-display').textContent = codeVerifier || "Not found in storage";
            document.getElementById('nonce-display').textContent = nonce || "Not found in storage";
            document.getElementById('state-display').textContent = state || "Not found in storage";

            console.log("--- Callback Page Loaded ---");
            console.log("Code Verifier (from storage):", codeVerifier);
            console.log("Nonce (from storage):", nonce);
            console.log("State (from storage):", state);

            let accessToken = null;

            function callApi() {{
                if (!accessToken) {{
                    document.getElementById('api-result').textContent = "Cannot call API: No Access Token.";
                    return;
                }}
                const headers = {{ 'Authorization': 'Bearer ' + accessToken }};
                fetch('{API_BASE_URL}/api/add/1/2', {{ headers }})
                    .then(res => res.ok ? res.json() : res.text().then(text => Promise.reject(res.status + " " + res.statusText + ": " + text)))
                    .then(data => {{
                        document.getElementById('api-result').textContent = data.result !== undefined ? data.result : JSON.stringify(data);
                    }})
                    .catch(err => {{
                        document.getElementById('api-result').textContent = "API Error: " + err;
                    }});
            }}

            // Exchange authorization code for access token using PKCE.
            async function exchangeCodeForToken() {{
                const tokenDisplay = document.getElementById('access-token-display');
                if (!codeVerifier) {{
                    tokenDisplay.textContent = "ERROR: code_verifier not found in sessionStorage. Please start login flow again.";
                    return;
                }}

                const payload = new URLSearchParams({{
                    grant_type: 'authorization_code',
                    code: '{code}',
                    redirect_uri: '{OIDC_REDIRECT_URI}',
                    client_id: '{OIDC_CLIENT_ID}',
                    code_verifier: codeVerifier
                }});

                try {{
                    console.log("--- Token Exchange Request 2---");
                    console.log("Endpoint:", `{token_endpoint}`);
                    console.log("Payload:", payload.toString());

                    const response = await fetch(`{token_endpoint}`, {{ method: 'POST', headers: {{'Content-Type': 'application/x-www-form-urlencoded'}}, body: payload }});

                    console.log("--- Token Exchange Response ---");
                    console.log("Status:", response.status, response.statusText);
                    const data = await response.json();
                    console.log("Body:", data);

                    if (data.access_token) {{
                        accessToken = data.access_token;
                        tokenDisplay.textContent = accessToken;
                        fetchUserInfo(accessToken);
                    }} else {{
                        tokenDisplay.textContent = "ERROR: " + (data.error_description || JSON.stringify(data));
                    }}
                }} catch (err) {{
                    tokenDisplay.textContent = "FATAL: " + err;
                }}
            }}

            async function fetchUserInfo(token) {{
                const display = document.getElementById('userinfo-display');
                display.textContent = "Fetching...";
                try {{
                    console.log("--- Fetching User Info ---");
                    const res = await fetch(`{userinfo_endpoint}`, {{
                        headers: {{ 'Authorization': `Bearer ${{token}}` }}
                    }});
                    console.log("User Info Status:", res.status);
                    const info = await res.json();
                    console.log("User Info Body:", info);
                    display.textContent = JSON.stringify(info, null, 2);
                }} catch (e) {{
                    display.textContent = "Failed to fetch user info: " + e;
                }}
            }}

            exchangeCodeForToken();
        </script>
    </body>
    </html>
    """

# --- Main execution ---

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple App Server for OIDC tests")
    parser.add_argument("--port", type=int, default=7443,
                        help="Port (default: 7443)")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")

    args = parser.parse_args()
    print(f"Serving on {args.host}:{args.port}")
    app.run(server=MultiThreadedServer, host=args.host, port=args.port)
