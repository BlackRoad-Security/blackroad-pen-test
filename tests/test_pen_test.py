\"\"\"Tests for blackroad-pen-test.\"\"\"
import sys, os, socket
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from src.pen_test import (
    TestTarget, PortScanResult, NetworkScanResult,
    check_ssl_cert, check_headers, check_cors, check_rate_limiting,
    _probe_port, detect_ioc_type,
)

class TestTestTarget:
    def test_url_https_default_port(self):
        t = TestTarget(\"example.com\", 443, \"https\")
        assert t.url == \"https://example.com\"

    def test_url_custom_port(self):
        t = TestTarget(\"example.com\", 8080, \"https\")
        assert \":8080\" in t.url

    def test_url_http(self):
        t = TestTarget(\"example.com\", 80, \"http\")
        assert t.url == \"http://example.com\"

class TestPortScanResult:
    def test_dataclass_fields(self):
        r = PortScanResult(\"127.0.0.1\", 80, True, \"Apache\", \"HTTP\")
        assert r.host == \"127.0.0.1\"
        assert r.open is True
        assert r.service_hint == \"HTTP\"

    def test_closed_port(self):
        r = PortScanResult(\"127.0.0.1\", 9999, False)
        assert not r.open

class TestNetworkScanResult:
    def test_add_finding(self):
        r = NetworkScanResult(\"http://test.com\", \"2024-01-01T00:00:00Z\")
        r.add_finding(\"HIGH\", \"SSL_ISSUE\", \"cert expired\")
        assert len(r.findings) == 1
        assert r.findings[0][\"severity\"] == \"HIGH\"

    def test_to_dict(self):
        r = NetworkScanResult(\"http://test.com\", \"2024-01-01T00:00:00Z\")
        d = r.to_dict()
        assert \"target\" in d
        assert \"findings\" in d

class TestProbePort:
    def test_closed_port_returns_false(self):
        result = _probe_port(\"127.0.0.1\", 19999, 0.5)
        assert result.open is False

    def test_open_localhost_port(self):
        # Create a local server to test against
        import threading
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((\"127.0.0.1\", 0))
        port = server.getsockname()[1]
        server.listen(1)
        server.settimeout(2)
        def accept(): 
            try: server.accept()
            except: pass
        t = threading.Thread(target=accept, daemon=True)
        t.start()
        result = _probe_port(\"127.0.0.1\", port, 1.0)
        server.close()
        assert result.open is True

class TestCheckHeaders:
    def test_returns_dicts(self):
        # Won't actually connect; just test structure with offline target
        headers, issues = check_headers(\"http://127.0.0.1:19998\", timeout=0.1)
        assert isinstance(headers, dict)
        assert isinstance(issues, list)
        assert any(\"CONNECTION_FAILED\" in i for i in issues)