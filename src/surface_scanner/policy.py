from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from .targets import TargetPolicyError, resolve_target


@dataclass(frozen=True)
class ScanPolicy:
    """Safety controls shared by CLI, scheduler, and web UI."""

    authorized: bool
    authorized_targets: frozenset[str] = frozenset()
    max_ports: int = 128

    def validate(self, target: str) -> str:
        if not self.authorized:
            raise TargetPolicyError("Explicit authorization is required")
        resolved = resolve_target(target, allow_public=bool(self.authorized_targets))
        if resolved in self.authorized_targets or target in self.authorized_targets:
            return resolved
        address = ip_address(resolved)
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise TargetPolicyError("Public targets must be present in the authorization allowlist")
        return resolved


def load_allowlist(path: str | None) -> frozenset[str]:
    if not path:
        return frozenset()
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            entries.append(value)
            try:
                entries.append(resolve_target(value, allow_public=True))
            except TargetPolicyError:
                pass
    return frozenset(entries)