import socket
from concurrent.futures import ThreadPoolExecutor

from .models import Finding, Observation
from .adapters import scan_with_nmap
from .checks import configuration_checks, http_checks, tls_checks
from .cve import lookup


def _probe(target: str, port: int, timeout: float) -> Observation | None:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return Observation(target=target, port=port)
    except (TimeoutError, OSError):
        return None


def scan_tcp(target: str, ports: list[int], timeout: float = 0.5, workers: int = 32) -> list[Observation]:
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        results = pool.map(lambda port: _probe(target, port, timeout), ports)
    return [item for item in results if item is not None]


def observations_to_findings(observations: list[Observation]) -> list[Finding]:
    findings = [
        Finding(
            title="Exposed TCP service requires review",
            severity="info",
            score=0.0,
            target=item.target,
            port=item.port,
            evidence=item.evidence,
            remediation="Identify the service owner and restrict exposure to required networks.",
        )
        for item in observations
    ]
    findings.extend(configuration_checks(observations))
    for item in observations:
        if item.port in {80, 8080, 8000, 443, 8443}:
            findings.extend(http_checks(item.target, item.port))
        if item.port in {443, 465, 636, 8443}:
            findings.extend(tls_checks(item.target, item.port))
        for record in lookup(item.product, item.version):
            findings.append(Finding(
                title=f"Possible known vulnerability: {record.cve}",
                severity=record.severity,
                score=record.cvss,
                target=item.target,
                port=item.port,
                cves=(record.cve,),
                evidence=f"Detected product={item.product!r}, version={item.version!r}; {record.description}",
                remediation="Confirm the exact version and apply the vendor patch or mitigation.",
                source="cve-catalog",
                confidence="low",
                cvss_vector=f"CVSS base score {record.cvss}",
            ))
    return findings


def scan(target: str, ports: list[int], timeout: float = 0.5, prefer_nmap: bool = True) -> tuple[list[Observation], str]:
    if prefer_nmap:
        try:
            return scan_with_nmap(target, ports, timeout), "nmap"
        except (FileNotFoundError, OSError, RuntimeError, TimeoutError, ValueError):
            pass
    return scan_tcp(target, ports, timeout=timeout), "native-fallback"
