import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Finding, Observation


def http_checks(target: str, port: int, timeout: float = 3.0) -> list[Finding]:
    scheme = "https" if port in {443, 8443} else "http"
    url = f"{scheme}://{target}:{port}/"
    findings: list[Finding] = []
    try:
        request = Request(url, headers={"User-Agent": "authorized-surface-scanner/0.1"}, method="GET")
        with urlopen(request, timeout=timeout, context=ssl._create_unverified_context() if scheme == "https" else None) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            if scheme == "http":
                findings.append(Finding("HTTP service is not encrypted", "medium", 5.0, target, port, evidence=url, remediation="Use HTTPS and redirect HTTP to HTTPS.", source="http"))
            required = {"content-security-policy", "x-content-type-options", "strict-transport-security"}
            missing = sorted(required - headers.keys())
            if missing:
                findings.append(Finding("Missing HTTP security headers", "low", 2.0, target, port, evidence=", ".join(missing), remediation="Configure the missing security headers for the application.", source="http"))
            if response.status in {200, 204}:
                findings.append(Finding("HTTP endpoint responded without authentication", "info", 0.0, target, port, evidence=f"GET / returned HTTP {response.status}", remediation="Confirm this endpoint is intentionally public; no credentials were tested.", source="http", confidence="low"))
    except (HTTPError, URLError, TimeoutError, OSError):
        pass
    return findings


def tls_checks(target: str, port: int, timeout: float = 3.0) -> list[Finding]:
    findings: list[Finding] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=target) as secure:
                certificate = secure.getpeercert()
                if not certificate:
                    return findings
                cipher = secure.cipher()
                if cipher and cipher[1] in {"TLSv1", "TLSv1.1"}:
                    findings.append(Finding("Deprecated TLS protocol", "high", 8.0, target, port, evidence=cipher[1], remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or newer.", source="tls"))
    except (ssl.SSLError, OSError, TimeoutError):
        pass
    return findings


def configuration_checks(observations: list[Observation]) -> list[Finding]:
    findings = []
    for item in observations:
        if item.port in {21, 23, 445, 3389}:
            findings.append(Finding("High-risk administrative or legacy service exposed", "high", 8.0, item.target, item.port, evidence=f"TCP/{item.port} open", remediation="Restrict the service to a management network or disable it when unused.", source="configuration"))
    return findings