import re
import subprocess

from .models import Observation


def scan_local_endpoints() -> list[Observation]:
    """Inventory local listening TCP endpoints using the Windows netstat utility."""
    result = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=10)
    observations: list[Observation] = []
    pattern = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)", re.IGNORECASE)
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match:
            observations.append(Observation(target="localhost", port=int(match.group(2)), service=f"PID {match.group(3)}", evidence=f"Local listener on {match.group(1)}:{match.group(2)}"))
    return observations