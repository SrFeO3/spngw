import subprocess
import json
import pytest
from pathlib import Path
from datetime import datetime

OHA_CMD_BASE = [
    "oha",
    "--insecure",
    "--host", "localhost",
    "--"
]

# -------------------------------
# Fixture: run_dir for performance logs
# -------------------------------
@pytest.fixture(scope="session")
def perf_run_dir():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path("integration_tests/reports") / ts / "performance"
    path.mkdir(parents=True, exist_ok=True)
    return path

# -------------------------------
# Helper: run oha and save JSON
# -------------------------------
def run_oha(url, num_requests, run_dir: Path, test_name: str, concurrency=None):
    cmd = [
        "oha",
        "--insecure",
        "--host", "check.test.example.com",
        "--connect-to", "check.test.example.com:8443:127.0.0.1:8443",
        url,
        "-n", str(num_requests),
        "--output-format", "json"
    ]
    if concurrency:
        cmd += ["-c", str(concurrency)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"oha failed:\nstdout={result.stdout}\nstderr={result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail(f"Failed to parse JSON from oha output:\n{result.stdout}")

    # Save JSON
    json_file = run_dir / f"{test_name}.json"
    with json_file.open("w") as f:
        json.dump(data, f, indent=2)

    if not all(r["status"] == 200 for r in data.get("results", [])):
        pytest.fail(f"Some requests failed:\n{result.stdout}")

    return data

# -------------------------------
# Performance tests
# -------------------------------
@pytest.mark.performance
def test_smoke_load(perf_run_dir):
    """Low load / smoke test"""
    run_oha(
        "https://check.test.example.com:8443/sleep/1",
        num_requests=20,
        run_dir=perf_run_dir,
        test_name="smoke_load"
    )

@pytest.mark.performance
def test_concurrency(perf_run_dir):
    """Concurrent requests test"""
    run_oha(
        "https://check.test.example.com:8443/health",
        num_requests=50,
        concurrency=10,
        run_dir=perf_run_dir,
        test_name="concurrency"
    )

@pytest.mark.performance
def test_large_response(perf_run_dir):
    """Large response test"""
    run_oha(
        "https://check.test.example.com:8443/large-body",
        num_requests=10,
        run_dir=perf_run_dir,
        test_name="large_response"
    )
