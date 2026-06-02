#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Web Server (multithreaded, multi-port) for test
v0.2: JSON response support.
Run:   python httpserver.py --ports 8080

Usage:
  1) Install dependency:
       pip install bottle
  2) Run the server on multiple ports (comma or space separated):
       python httpserver.py --ports 8000,8001,8080
       # or
       python httpserver.py --ports "8000 8001 8080" --host 127.0.0.1
  3) Try the endpoints:
       curl -i http://localhost:8000/
       curl -i http://localhost:8001/hello
       curl -i http://localhost:8080/sleep/3
       curl -i http://localhost:8080/xsleep/3/10/5
       curl -N -v http://localhost:8080/xsleep/2/3/4 2>&1 | ts
       curl -i http://localhost:8000/error/503
       curl -i http://localhost:8001/not-found

Features:
  - Multi-threaded WSGI server (handles concurrent requests).
  - Listen on multiple ports with the same Bottle app.
  - All pages show: request start time, end time, page path, HTTP status, and elapsed milliseconds.
  - Endpoints:
      /                       -> "hello from /"
      /hello                  -> "hello from /hello"
      (and /fruit/apple/hello, /fruit/orange/hello, /api/test)
      /sleep/<n>              -> wait n seconds (integer)
      /xsleep/<a>/<b>/<c>     -> wait a sec before headers, b sec after headers, c sec body
      /error/<XXX>            -> return status XXX (clamped to 100 - 599, otherwise 400)
      /close                  -> close the connection abruptly
"""

import time
from datetime import datetime
import threading
import re
import json

from bottle import Bottle, request, response, ServerAdapter

# Threaded WSGI server via standard library (no extra deps)
from wsgiref.simple_server import make_server, WSGIRequestHandler, WSGIServer
from socketserver import ThreadingMixIn


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """WSGI server that handles each request in a separate thread."""
    daemon_threads = True  # Ensure worker threads shut down cleanly


class MultiThreadedServer(ServerAdapter):
    """Bottle ServerAdapter bound to the threaded WSGI server."""
    def run(self, handler):
        httpd = make_server(self.host, self.port, handler,
                            server_class=ThreadingWSGIServer,
                            handler_class=WSGIRequestHandler)
        httpd.serve_forever()


app = Bottle()


@app.hook('before_request')
def before():
    """Capture request start timestamps (wall time and perf counter)."""
    request.environ['req_start_perf'] = time.perf_counter()
    request.environ['req_start_dt'] = datetime.now().astimezone().isoformat(timespec='milliseconds')


def render_page(message: str, status: int | None = None) -> str:
    """
    Common renderer for all responses.
    - Optionally set HTTP status.
    - Compute end time and elapsed processing time.
    - Return consistent JSON body for all responses.
    """
    if status is not None:
        response.status = int(status)

    end_dt = datetime.now().astimezone().isoformat(timespec='milliseconds')
    start_perf = request.environ.get('req_start_perf')
    elapsed_ms = (time.perf_counter() - start_perf) * 1000 if start_perf is not None else None

    response.content_type = 'application/json'

    # Build the full response data
    data = {
        "message": message,
        "path": request.path,
        "status": response.status,
        "start": request.environ.get('req_start_dt'),
        "end": end_dt,
        "elapsed_ms": round(elapsed_ms, 1) if elapsed_ms is not None else None,
        "request_headers": dict(request.headers),
        "response_headers": dict(response.headers)
    }

    return json.dumps(data, indent=2)

# ---- Routes ----

@app.route('<:re:.*>', method=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def standard_pages():
    """
    Catch-all route that echoes headers and path.
    """
    return render_page(f"Echo response from {request.path}")

@app.get('/sleep/<num:int>')
def sleep(num: int):
    """
    Sleep for <num> seconds (integer).
    Using Bottle's <int> converter ensures non-negative integer.
    """
    time.sleep(num)
    return render_page(f"slept {num} seconds")

@app.get('/xsleep/<x:int>/<y:int>/<z:int>')
def xsleep(x: int, y: int, z: int):
    """
    Sleep for X seconds before sending headers,
    then Y seconds after headers, then Z seconds during body streaming.
    """
    # Step 1: Sleep before sending headers
    time.sleep(x)

    response.content_type = 'application/json'

    def generate_body():
        yield '{\n  "steps": [\n'.encode()
        
        # Step 2: Sleep after headers (first byte sent triggers header transmission)
        time.sleep(y)
        yield f'    "slept {x}s before headers",\n'.encode()
        
        # Step 3: Sleep during body
        time.sleep(z)
        yield f'    "slept {y}s after headers and {z}s during body"\n'.encode()
        
        yield '  ]\n}'.encode()

    return generate_body()

@app.get('/error/<code:int>')
def error(code: int):
    """
    Return a forced HTTP error with the given code.
    Accepts 100 - 599; outside the range returns 400.
    """
    http_code = code if 100 <= code <= 599 else 400
    return render_page(f"forced error {http_code}", status=http_code)


def default_error_handler(error):
    """
    Replace Bottle's default error handler to always return our common format.
    This covers 404, 500, and any other HTTP errors not explicitly routed.
    """
    response.status = error.status_code
    return render_page(f"error {error.status_code}")

# Override the default error handler
app.default_error_handler = default_error_handler


def run_on_ports(app: Bottle, ports: list[int], host: str = '0.0.0.0'):
    """
    Run the same Bottle app on multiple ports simultaneously.
    Each port is served by a dedicated thread using the threaded WSGI server.
    """
    threads: list[threading.Thread] = []
    for p in ports:
        adapter = MultiThreadedServer(host=host, port=p)
        t = threading.Thread(target=lambda: app.run(server=adapter, quiet=True))
        t.daemon = True
        t.start()
        threads.append(t)

    print(f"Serving on {host} ports: {', '.join(map(str, ports))}")
    print("Endpoints: '/', '/hello', '/sleep/<num>', '/error/<code>', '/api/test', etc.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple Bottle Web Server (multithreaded, multi-port)")
    parser.add_argument("--ports", type=str, default="8080",
                        help="Comma- or space-separated ports (e.g., '8080,8081 9090')")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")

    args = parser.parse_args()
    # Allow both comma and whitespace as delimiters
    ports = [int(x) for x in re.split(r"[,\s]+", args.ports) if x]

    run_on_ports(app, ports=ports, host=args.host)
