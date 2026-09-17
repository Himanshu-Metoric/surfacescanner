from dataclasses import dataclass


@dataclass(frozen=True)
class CveRecord:
    cve: str
    product: str
    severity: str
    cvss: float
    description: str


# Conservative seed catalog. Production deployments can replace this with an approved, cached feed.
CATALOG = (
    CveRecord("CVE-2014-0160", "openssl", "high", 7.5, "Heartbleed affects vulnerable OpenSSL releases."),
    CveRecord("CVE-2017-0144", "microsoft smb", "critical", 9.8, "EternalBlue affects vulnerable SMBv1 systems."),
    CveRecord("CVE-2021-44228", "log4j", "critical", 10.0, "Log4Shell affects vulnerable Log4j deployments."),
)


def lookup(product: str | None, version: str | None) -> list[CveRecord]:
    if not product:
        return []
    normalized = product.lower()
    return [record for record in CATALOG if record.product in normalized]