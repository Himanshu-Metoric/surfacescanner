import time
from datetime import datetime, timezone

from .policy import ScanPolicy
from .scanner import observations_to_findings, scan
from .risk import score_findings


def run_schedule(target: str, ports: list[int], policy: ScanPolicy, interval: int, runs: int = 1) -> None:
    interval = max(1, int(interval))
    runs = max(1, int(runs))

    for run_number in range(runs):
        resolved = policy.validate(target)
        observations, engine = scan(resolved, ports)
        findings = observations_to_findings(observations)
        print(f"{datetime.now(timezone.utc).isoformat()} run={run_number + 1} engine={engine} risk={score_findings(findings)}/10")
        if run_number + 1 < runs:
            time.sleep(interval)