import subprocess
import pytest
import time
import urllib3
from pathlib import Path
from datetime import datetime

@pytest.fixture(scope="session")
def run_dir():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path("reports") / ts
    path.mkdir(parents=True, exist_ok=True)
    return path

@pytest.fixture
def resolve_to_localhost(request):
    """
    A pytest fixture that temporarily overrides DNS resolution for a specific
    hostname to point to 127.0.0.1, mimicking `curl --resolve`.

    It must be parameterized with the hostname to resolve, e.g.:
    @pytest.mark.parametrize("resolve_to_localhost", ["www.example.com"], indirect=True)
    """
    hostname_to_resolve = request.param
    original_dns_lookup = urllib3.util.connection.create_connection
    urllib3.util.connection.create_connection = lambda address, *args, **kwargs: original_dns_lookup(("127.0.0.1", address[1]), *args, **kwargs)
    yield
    urllib3.util.connection.create_connection = original_dns_lookup


# python httpserver.py --ports "9000 9001 9002 9003 9004"
@pytest.fixture(scope="session", autouse=True)
def start_mocks(run_dir):
    mock_log = open(run_dir / "mock_server.log", "w")
    broken_log = open(run_dir / "broken_http.log", "w")
    p1 = subprocess.Popen(["python", "mock_servers/httpserver.py", "--ports", "9000 9001 9002 9003 9004"],
        stdout=mock_log,
        stderr=subprocess.STDOUT,
    )
    p2 = subprocess.Popen(["python", "mock_servers/badhttpserver.py"],
        stdout=broken_log,
        stderr=subprocess.STDOUT,
    )
    time.sleep(1)
    yield
    p1.terminate()
    p2.terminate()
    mock_log.close()
    broken_log.close()

# APIGW_INVENTORY_URL="http://localhost:3000/v1" RUST_LOG=info cargo run
#@pytest.fixture(scope="session", autouse=True)
#def start_bff():
#    p = subprocess.Popen(["cargo", "run"])
#    time.sleep(2)
#    yield
#    p.terminate()

@pytest.fixture(scope="session")
def test_config():
    config_path = Path(__file__).parent / "config" / "test_config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def bff_base_url(test_config):
    return test_config["bff"]["base_url"]
