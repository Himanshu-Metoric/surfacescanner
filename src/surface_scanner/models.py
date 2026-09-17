from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Observation:
    target: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    os_guess: str | None = None
    evidence: str = "TCP connect succeeded"


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    score: float
    target: str
    port: int | None = None
    cves: tuple[str, ...] = ()
    evidence: str = ""
    remediation: str = ""
    source: str = "native"
    confidence: str = "medium"
    cvss_vector: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
