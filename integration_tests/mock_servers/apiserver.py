#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple API Server (multithreaded) for integration tests.

Protected API backend requiring OIDC authentication (Bearer token).
Supports JWS (Signed) and JWE (Encrypted) tokens.
"""

# --- OIDC Configuration ---
# Select the provider by commenting/uncommenting the desired section.
# OIDC Configuration for OKTA
OIDC_ISSUER_URL = "https://xxx/oauth2/default"
OIDC_AUDIENCE = "https://procyon.test.example.com:8443/"

# If you expect JWE (Encrypted Tokens), set the decryption key here.
# For 'alg: dir', this is the shared secret. For RSA, this is the PEM private key.
JWE_DECRYPTION_KEY = None

import time
import threading
from datetime import datetime
import re
import requests
from jose import jwt, jwk
from jose.exceptions import JWTClaimsError
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

# --- JWT Validation Cache ---
JWKS_CACHE = {}

def get_jwks():
    """Fetches and caches JWKS using OIDC Discovery."""
    # Simple in-memory cache.
    if "keys" in JWKS_CACHE:
        return JWKS_CACHE["keys"]

    # 1. Fetch OIDC Discovery Document
    discovery_url = f"{OIDC_ISSUER_URL.rstrip('/')}/.well-known/openid-configuration"
    print(f" > Fetching OIDC Discovery from {discovery_url}")
    disc_resp = requests.get(discovery_url, timeout=5)
    disc_resp.raise_for_status()
    discovery_doc = disc_resp.json()
    jwks_uri = discovery_doc.get('jwks_uri')
    print(f" > Discovery successful. jwks_uri: {jwks_uri}")

    # 2. Fetch JWKS
    print(f" > Fetching JWKS from {jwks_uri}")
    response = requests.get(jwks_uri, timeout=5)
    response.raise_for_status()
    jwks = response.json()
    print(f" > Fetched JWKS content: {jwks}")
    JWKS_CACHE["keys"] = jwks["keys"]
    print(f" > Successfully fetched and cached {len(jwks['keys'])} key(s).")
    return jwks["keys"]


@app.hook('after_request')
def enable_cors():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'

@app.route('/api/add/<x:int>/<y:int>', method=['GET', 'OPTIONS'])
@app.route('/protected/api/add/<x:int>/<y:int>', method=['GET', 'OPTIONS'])
@app.route('/protected2/api/add/<x:int>/<y:int>', method=['GET', 'OPTIONS'])
def add_api(x, y):
    """
    Protected API adding two numbers. Requires Bearer token.
    """
    if request.method == 'OPTIONS':
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.url} - Responding to OPTIONS preflight.")
        return {}

    # --- Debug Logging ---
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.url}")
    print(f" > Host: {request.headers.get('Host')}")
    print(f" > Origin: {request.headers.get('Origin')}")
    for k, v in request.headers.items():
        print(f" > Header: {k}: {v}")

    auth_header = request.headers.get('Authorization')
    response.content_type = 'application/json'

    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(" ", 1)[1]
        print(f" > Bearer token found. Validating as JWT...")
        print(f" > Token: {token}")

        try:
            # A JWE has 5 parts, a JWS has 3.
            token_parts = token.split('.')
            token_category = "Unknown"
            validation_result = "Unknown"

            if len(token_parts) == 5:
                # Handle as JWE (Encrypted)
                print(f" > Token appears to be JWE (5 parts). Attempting decryption...")

                if not JWE_DECRYPTION_KEY:
                    raise Exception("Received JWE token but JWE_DECRYPTION_KEY is not configured in apiserver.py.")

                # Decrypt and validate JWE
                # python-jose handles decryption if the key is provided.
                payload = jwt.decode(
                    token,
                    JWE_DECRYPTION_KEY,
                    audience=OIDC_AUDIENCE,
                    issuer=OIDC_ISSUER_URL
                )
                token_category = "JWE"
                validation_result = "Decrypted & Validated"
            elif len(token_parts) == 3:
                # Handle as JWS (Signed)
                print(f" > Token appears to be JWS (3 parts). Verifying signature...")

                try:
                    unverified_header = jwt.get_unverified_header(token)
                except Exception as e:
                    print(f" > PRE-VALIDATION FAILED: Could not decode token header. Error: {e}")
                    raise Exception(f"Token header decode failed. Is it a valid JWT? Error: {e}")

                print(f" > Unverified Token Header: {unverified_header}")

                jwks = get_jwks()
                kid = unverified_header.get("kid")
                if not kid:
                    raise Exception("Token header does not contain 'kid' (Key ID)")

                print(f" > Token KID: {kid}")

                rsa_key = {}
                for key in jwks:
                    if key.get("kid") == kid:
                        rsa_key = key
                        break # Found the key

                if not rsa_key:
                    raise Exception(f"Unable to find a matching key for KID '{kid}' in JWKS")

                print(f" > Found key for KID: {kid}. Validating...")

                # Validate signature, expiration, issuer, and audience.
                try:
                    payload = jwt.decode(
                        token, rsa_key, algorithms=["RS256"],
                        audience=OIDC_AUDIENCE,
                        issuer=OIDC_ISSUER_URL
                    )
                except Exception as e:
                    print(f" > VALIDATION FAILED: {e.__class__.__name__} - {e}")
                    if isinstance(e, JWTClaimsError):
                        print(f" > EXPECTED: issuer={OIDC_ISSUER_URL}, audience={OIDC_AUDIENCE}")
                        try:
                            claims = jwt.get_unverified_claims(token)
                            print(f" > RECEIVED: issuer={claims.get('iss')}, audience={claims.get('aud')}")
                        except Exception:
                            pass
                    raise e
                token_category = "JWT"
                validation_result = "Signature Verified"
            else:
                # Treat formats other than JWT/JWE as Opaque Tokens and consider validation successful
                print(f" > Token parts count is {len(token_parts)}. Treating as Opaque Token and skipping validation.")
                payload = {'sub': 'opaque-user', 'name': 'Opaque User', 'scope': 'unknown'}
                token_category = "Opaque"
                validation_result = "Skipped"

            print(f" > Decision: Authenticated.")
            print(f" > Payload: {payload}")

            result = x + y

            bff_user = request.headers.get('X-BFF-IDToken-Sub', 'None')
            return {'result': result, 'comment': f"Key: {token_category}, Validation: {validation_result}", 'user': bff_user}

        except Exception as e:
            print(f" > Decision: Not Authenticated (JWT validation failed: {e.__class__.__name__}: {e})")
            response.status = 401
            return {'error': f'Token validation failed: {e}'}
    else:
        print(" > Decision: Not Authenticated (No/Invalid Bearer token)")
        response.status = 401
        return {'error': 'Authentication required'}

# --- Main execution ---

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple API Server for OIDC tests")
    parser.add_argument("--port", type=int, default=7444,
                        help="Port (default: 7444)")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")

    args = parser.parse_args()
    print(f"Serving on {args.host}:{args.port}")
    app.run(server=MultiThreadedServer, host=args.host, port=args.port)
