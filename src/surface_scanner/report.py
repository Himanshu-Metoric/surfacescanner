import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import Finding, Observation


def write_csv(path: str | Path, findings: list[Finding]) -> None:
    fields = ["title", "severity", "score", "target", "port", "cves", "evidence", "remediation"]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["cves"] = ", ".join(finding.cves)
            row.pop("metadata", None)
            writer.writerow(row)


def write_json(path: str | Path, observations: list[Observation], findings: list[Finding], risk_score: float) -> None:
    payload = {
        "risk_score": risk_score,
        "observations": [asdict(item) for item in observations],
        "findings": [asdict(item) for item in findings],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_text(path: str | Path, target: str, observations: list[Observation], findings: list[Finding], risk_score: float) -> None:
    lines = [f"Authorized Surface Scanner report for {target}", f"Risk score: {risk_score}/10", "", "Observations:"]
    if observations:
        lines.extend(f"- TCP/{item.port}: {item.service or 'unknown'} {item.product or ''} {item.version or ''} ({item.evidence})" for item in observations)
    else:
        lines.append("- No open observations detected")
    lines.append("")
    lines.append("Findings:")
    if findings:
        lines.extend(f"- [{item.severity.upper()} {item.score}] {item.title} on {item.target}:{item.port or '-'} | {item.evidence} | Fix: {item.remediation}" for item in findings)
    else:
        lines.append("- No findings detected")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_pdf(path: str | Path, target: str, observations: list[Observation], findings: list[Finding], risk_score: float) -> None:
    """Write a dependency-free, readable PDF using a minimal PDF text document."""
    lines = [f"Authorized Surface Scanner - {target}", f"Risk score: {risk_score}/10", "", "Observations:"]
    if observations:
        lines.extend(f"TCP/{item.port} {item.service or 'unknown'} {item.product or ''} {item.version or ''}" for item in observations)
    else:
        lines.append("No open observations detected")
    lines.append("Findings:")
    if findings:
        lines.extend(f"{item.severity.upper()} {item.score}: {item.title} ({item.target}:{item.port or '-'})" for item in findings)
        lines.extend(f"Evidence: {item.evidence}" for item in findings)
    else:
        lines.append("No findings detected")

    sanitized = []
    for line in lines:
        text = str(line)[:110].replace("(", "\\(").replace(")", "\\)").replace("\\", "\\\\")
        sanitized.append(text)
    if not sanitized:
        sanitized = ["No report data"]
    stream = "BT /F1 10 Tf 48 760 Td " + " Tj 0 -14 Td ".join(f"({line})" for line in sanitized) + " ET"
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", f"<< /Length {len(stream.encode('ascii', 'replace'))} >>\nstream\n{stream}\nendstream"]
    pdf = "%PDF-1.4\n"; offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf.encode("ascii"))); pdf += f"{index} 0 obj\n{obj}\nendobj\n"
    xref = len(pdf.encode("ascii")); pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n" + "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    Path(path).write_bytes(pdf.encode("ascii", "replace"))
