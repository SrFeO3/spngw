#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Web Server (multithreaded, multi-port) for test
version 0.1

Usage:
  1) Install dependency:
       pip install bottle
  2) Run the server on multiple ports (comma or space separated):
       python server.py --ports 8000,8001,8080
       # or
       python server.py --ports "8000 8001 8080" --host 127.0.0.1
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
    - Return consistent text/plain body across success and error paths.
    """
    if status is not None:
        response.status = int(status)

    end_dt = datetime.now().astimezone().isoformat(timespec='milliseconds')
    start_perf = request.environ.get('req_start_perf')
    elapsed_ms = (time.perf_counter() - start_perf) * 1000 if start_perf is not None else None

    status_line = str(response.status)  # e.g., "200 OK"

    lines = [
        f"message: {message}",
        f"page: {request.path}",
        f"status: {status_line}",
        f"start: {request.environ.get('req_start_dt')}",
        f"end: {end_dt}",
    ]
    if elapsed_ms is not None:
        lines.append(f"elapsed_ms: {elapsed_ms:.1f}")

    response.content_type = 'text/plain; charset=UTF-8'

    lines.append("")
    lines.append("--- Request Headers ---")
    for k, v in request.headers.items():
        lines.append(f"{k}: {v}")

    lines.append("")
    lines.append("--- Response Headers ---")
    for k, v in response.headers.items():
        lines.append(f"{k}: {v}")

    body = "\n".join(lines) + "\n"
    return body


# ---- Routes ----

@app.get(['/', '/hello', '/fruit/orange/juice', '/fruit/apple/juice', '/api/test'])
def standard_pages():
    """Return a standard 'hello' page with meta information for multiple routes."""
    return render_page(f"hello from {request.path}")

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

    # Step 2: Prepare headers
    response.content_type = 'text/html'

    def generate_body():
        # Start of body
        yield "<html><body>".encode()

        # Sleep after headers
        time.sleep(y)

        # Body content part 1
        yield f"Slept {x} seconds before headers<br>".encode()

        # Sleep during body
        time.sleep(z)

        # Body content part 2
        yield f"Slept {y} seconds after headers and {z} seconds during body".encode()

        # End of body
        yield "</body></html>".encode()

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
