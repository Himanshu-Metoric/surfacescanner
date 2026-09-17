import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import Observation


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def scan_with_nmap(target: str, ports: list[int], timeout: float = 5.0) -> list[Observation]:
    """Use Nmap XML output without scripts, exploit checks, or credential actions."""
    if not nmap_available():
        raise FileNotFoundError("nmap is not installed")
    port_spec = ",".join(str(port) for port in ports)
    command = ["nmap", "-Pn", "-T3", "--open", "-sV", "-O", "-p", port_spec, "-oX", "-", target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=max(5.0, timeout * len(ports)))
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "nmap failed")
    root = ET.fromstring(result.stdout)
    observations: list[Observation] = []
    os_guess = None
    osmatch = root.find(".//os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.attrib.get("name")
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        observations.append(Observation(
            target=target,
            port=int(port.attrib["portid"]),
            protocol=port.attrib.get("protocol", "tcp"),
            service=service.attrib.get("name") if service is not None else None,
            product=service.attrib.get("product") if service is not None else None,
            version=service.attrib.get("version") if service is not None else None,
            os_guess=os_guess,
            evidence="Nmap service/version detection succeeded",
        ))
    return observations