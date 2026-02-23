"""
BlackRoad Pen-Test Toolkit – stdlib-only network security scanner.
Uses only: socket, ssl, urllib, http.client, concurrent.futures, json, argparse.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class TestTarget:
    host: str
    port: int = 443
    scheme: str = "https"
    timeout: float = 5.0

    @property
    def url(self) -> str:
        if (self.scheme == "https" and self.port == 443) or \
           (self.scheme == "http" and self.port == 80):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class PortScanResult:
    host: str
    port: int
    open: bool
    banner: str = ""
    service_hint: str = ""


@dataclass
class NetworkScanResult:
    target: str
    scan_time: str
    open_ports: List[PortScanResult] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    http_headers: Dict[str, str] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    cors_issues: List[str] = field(default_factory=list)
    rate_limit_info: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, str]] = field(default_factory=list)

    def add_finding(self, severity: str, category: str, detail: str) -> None:
        self.findings.append({"severity": severity, "category": category, "detail": detail})

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["open_ports"] = [asdict(p) for p in self.open_ports]
        return d


# ─────────────────────────────────────────────
# Port scanner
# ─────────────────────────────────────────────

COMMON_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _probe_port(host: str, port: int, timeout: float) -> PortScanResult:
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendall(b"\r\n")
                data = sock.recv(256)
                banner = data.decode("utf-8", errors="replace").strip()[:120]
            except Exception:
                pass
            return PortScanResult(
                host=host, port=port, open=True,
                banner=banner,
                service_hint=COMMON_SERVICES.get(port, "unknown"),
            )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return PortScanResult(host=host, port=port, open=False)


def port_scan(
    host: str,
    port_range: Tuple[int, int] = (1, 1024),
    timeout: float = 1.0,
    max_workers: int = 100,
) -> List[PortScanResult]:
    """Scan *host* over *port_range* using concurrent socket probes."""
    start, end = port_range
    ports = list(range(start, end + 1))
    results: List[PortScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass
    results.sort(key=lambda r: r.port)
    return [r for r in results if r.open]


# ─────────────────────────────────────────────
# SSL/TLS certificate check
# ─────────────────────────────────────────────

def check_ssl_cert(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Inspect SSL certificate and protocol configuration."""
    info: Dict[str, Any] = {"host": host, "port": port, "issues": []}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host,
        ) as ssock:
            cert = ssock.getpeercert()
            info["subject"] = dict(x[0] for x in cert.get("subject", []))
            info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            info["not_after"] = cert.get("notAfter", "")
            info["not_before"] = cert.get("notBefore", "")
            info["serial_number"] = cert.get("serialNumber", "")
            info["version"] = cert.get("version", "")
            info["protocol"] = ssock.version()
            info["cipher"] = ssock.cipher()
            san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            info["san"] = san_list

            # Check expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days = (exp - datetime.now(timezone.utc)).days
                    info["days_until_expiry"] = days
                    if days < 0:
                        info["issues"].append("CERT_EXPIRED")
                    elif days < 30:
                        info["issues"].append(f"CERT_EXPIRING_SOON ({days}d)")
                except ValueError:
                    pass

            # Weak protocols
            proto = ssock.version() or ""
            if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                info["issues"].append(f"WEAK_PROTOCOL:{proto}")

            # Weak cipher
            cipher_name = (ssock.cipher() or [""])[0]
            if any(w in cipher_name for w in ("RC4", "DES", "NULL", "EXPORT", "anon")):
                info["issues"].append(f"WEAK_CIPHER:{cipher_name}")

    except ssl.CertificateError as e:
        info["issues"].append(f"CERT_ERROR:{e}")
    except ssl.SSLError as e:
        info["issues"].append(f"SSL_ERROR:{e}")
    except Exception as e:
        info["issues"].append(f"CONNECTION_ERROR:{e}")
    return info


# ─────────────────────────────────────────────
# HTTP security headers check
# ─────────────────────────────────────────────

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": ("HIGH", "Missing HSTS header – forces HTTPS."),
    "x-content-type-options": ("MEDIUM", "Missing X-Content-Type-Options (set to nosniff)."),
    "x-frame-options": ("MEDIUM", "Missing X-Frame-Options – clickjacking risk."),
    "content-security-policy": ("HIGH", "Missing Content-Security-Policy header."),
    "x-xss-protection": ("LOW", "Missing X-XSS-Protection header."),
    "referrer-policy": ("LOW", "Missing Referrer-Policy header."),
    "permissions-policy": ("LOW", "Missing Permissions-Policy header."),
    "cache-control": ("INFO", "Missing Cache-Control header."),
}

LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def check_headers(
    url: str,
    expected_headers: Optional[List[str]] = None,
    timeout: float = 8.0,
) -> Tuple[Dict[str, str], List[str]]:
    """
    Return (response_headers_dict, list_of_issues).
    Also checks for information-leaking headers.
    """
    issues: List[str] = []
    headers: Dict[str, str] = {}
    check_set = expected_headers or list(REQUIRED_SECURITY_HEADERS.keys())

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlackRoad-PenTest/1.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            for key, value in resp.headers.items():
                headers[key.lower()] = value
    except urllib.error.HTTPError as e:
        for key, value in e.headers.items():
            headers[key.lower()] = value
    except Exception as e:
        issues.append(f"CONNECTION_FAILED:{e}")
        return headers, issues

    for h in check_set:
        hl = h.lower()
        if hl not in headers:
            sev, desc = REQUIRED_SECURITY_HEADERS.get(hl, ("INFO", f"Missing header: {h}"))
            issues.append(f"MISSING_HEADER:{h}:{sev}:{desc}")

    for lh in LEAK_HEADERS:
        if lh in headers:
            issues.append(f"INFO_LEAK:{lh}:{headers[lh]}")

    return headers, issues


# ─────────────────────────────────────────────
# CORS check
# ─────────────────────────────────────────────

def check_cors(url: str, timeout: float = 8.0) -> List[str]:
    """Send a cross-origin preflight request and detect misconfigurations."""
    issues: List[str] = []
    origin = "https://evil.example.com"
    try:
        req = urllib.request.Request(
            url,
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
                "User-Agent": "BlackRoad-PenTest/1.0",
            },
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                h = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            h = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        issues.append(f"CORS_CHECK_FAILED:{e}")
        return issues

    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        issues.append("CORS_WILDCARD_ORIGIN:Allows any origin (ACAO: *).")
    elif acao == origin:
        issues.append("CORS_REFLECTED_ORIGIN:Server reflects arbitrary Origin header.")

    if acac == "true" and acao in ("*", origin):
        issues.append(
            "CORS_CREDENTIALS_WITH_WILDCARD:"
            "Credentials allowed with overly permissive ACAO – CSRF risk."
        )
    if not acao:
        issues.append("CORS_HEADER_ABSENT:No ACAO header found.")
    return issues


# ─────────────────────────────────────────────
# Rate-limit check
# ─────────────────────────────────────────────

def check_rate_limiting(url: str, requests: int = 50, timeout: float = 3.0) -> Dict[str, Any]:
    """Send *requests* sequential requests and detect if rate limiting is active."""
    statuses: List[int] = []
    rate_limited = False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.monotonic()
    for _ in range(requests):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BlackRoad-PenTest/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                statuses.append(resp.status)
        except urllib.error.HTTPError as e:
            statuses.append(e.code)
            if e.code in (429, 503):
                rate_limited = True
                break
        except Exception:
            statuses.append(0)
    elapsed = time.monotonic() - start

    count_4xx = sum(1 for s in statuses if 400 <= s < 500)
    return {
        "url": url,
        "requests_sent": len(statuses),
        "rate_limited": rate_limited,
        "elapsed_seconds": round(elapsed, 2),
        "status_429_count": statuses.count(429),
        "status_codes": dict(zip(*_count_items(statuses))),
        "assessment": (
            "RATE_LIMITED" if rate_limited else
            "POSSIBLE_RATE_LIMIT" if count_4xx / max(len(statuses), 1) > 0.3 else
            "NO_RATE_LIMIT_DETECTED"
        ),
    }


def _count_items(items: list) -> Tuple[list, list]:
    counts: Dict[Any, int] = {}
    for i in items:
        counts[i] = counts.get(i, 0) + 1
    return list(counts.keys()), list(counts.values())


# ─────────────────────────────────────────────
# Full scan orchestrator
# ─────────────────────────────────────────────

def run_full_scan(target: TestTarget, port_range: Tuple[int, int] = (1, 1024)) -> NetworkScanResult:
    result = NetworkScanResult(
        target=target.url,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    # Port scan
    print(f"  [*] Port scanning {target.host} ({port_range[0]}-{port_range[1]})...")
    result.open_ports = port_scan(target.host, port_range)
    for pr in result.open_ports:
        if pr.port in (23,) and pr.open:
            result.add_finding("HIGH", "INSECURE_SERVICE", f"Telnet open on port {pr.port}")
        if pr.port == 21 and pr.open:
            result.add_finding("MEDIUM", "INSECURE_SERVICE", "FTP open – use SFTP/FTPS")

    # SSL
    if target.scheme == "https" or target.port == 443:
        print(f"  [*] SSL check...")
        result.ssl_info = check_ssl_cert(target.host, target.port)
        for issue in result.ssl_info.get("issues", []):
            sev = "CRITICAL" if "EXPIRED" in issue or "ERROR" in issue else "HIGH"
            result.add_finding(sev, "SSL_ISSUE", issue)

    # Headers
    print(f"  [*] Header analysis...")
    result.http_headers, header_issues = check_headers(target.url)
    result.missing_headers = header_issues
    for issue in header_issues:
        parts = issue.split(":", 2)
        if parts[0] == "MISSING_HEADER":
            sev = parts[2] if len(parts) > 2 else "MEDIUM"
            result.add_finding(sev, "MISSING_SECURITY_HEADER", issue)
        elif parts[0] == "INFO_LEAK":
            result.add_finding("LOW", "INFORMATION_DISCLOSURE", issue)

    # CORS
    print(f"  [*] CORS check...")
    result.cors_issues = check_cors(target.url)
    for issue in result.cors_issues:
        sev = "HIGH" if "WILDCARD" in issue or "CREDENTIALS" in issue else "MEDIUM"
        result.add_finding(sev, "CORS_MISCONFIGURATION", issue)

    # Rate limiting
    print(f"  [*] Rate-limit probe (20 requests)...")
    result.rate_limit_info = check_rate_limiting(target.url, requests=20)
    if result.rate_limit_info["assessment"] == "NO_RATE_LIMIT_DETECTED":
        result.add_finding("MEDIUM", "NO_RATE_LIMITING",
                           "No rate limiting detected – brute-force risk.")
    return result


def generate_pentest_report(results: List[NetworkScanResult], output: str = "pentest_report.json") -> str:
    """Write a JSON pentest report and return the path."""
    report = {
        "report_type": "penetration_test",
        "generated": datetime.now(timezone.utc).isoformat(),
        "targets": len(results),
        "total_findings": sum(len(r.findings) for r in results),
        "results": [r.to_dict() for r in results],
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    return output


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Pen-Test – stdlib-only network scanner")
    p.add_argument("host", help="Target hostname or IP")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--scheme", choices=["http", "https"], default="https")
    p.add_argument("--port-range", default="1-1024",
                   help="Port range to scan e.g. 1-1024 (default) or 22-443")
    p.add_argument("--output", "-o", default="pentest_report.json")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args(argv)

    start_p, end_p = (int(x) for x in args.port_range.split("-"))
    target = TestTarget(args.host, args.port, args.scheme, args.timeout)

    print(f"\n{'='*60}")
    print(f"  BlackRoad Pen-Test")
    print(f"  Target : {target.url}")
    print(f"{'='*60}\n")

    result = run_full_scan(target, (start_p, end_p))

    print(f"\n  Open ports: {len(result.open_ports)}")
    for pr in result.open_ports:
        print(f"    {pr.port:>5}/tcp  {pr.service_hint:<12}  {pr.banner[:60]}")

    print(f"\n  Findings: {len(result.findings)}")
    for f in sorted(result.findings, key=lambda x: x["severity"]):
        print(f"    [{f['severity']:<8}] {f['category']}: {f['detail'][:80]}")

    report_path = generate_pentest_report([result], args.output)
    print(f"\n  Report saved: {report_path}\n")
    return 1 if any(f["severity"] in ("CRITICAL","HIGH") for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
