from .models import Finding

SEVERITY_WEIGHT = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0, "info": 0.0}


def score_findings(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    weighted = sum(SEVERITY_WEIGHT.get(item.severity, 0.0) for item in findings)
    return round(min(10.0, weighted / len(findings)), 1)


def risk_label(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "informational"
