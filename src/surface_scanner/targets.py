import ipaddress
import socket
from urllib.parse import urlparse


class TargetPolicyError(ValueError):
    """Raised when a target is outside the explicit safe assessment policy."""


def classify_target(value: str) -> str:
    """Return one of: ip, hostname, url."""
    text = (value or "").strip()
    if not text:
        raise TargetPolicyError("Target is empty")
    if "://" in text:
        return "url"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    parsed = urlparse(f"//{text}")
    if parsed.hostname:
        return "hostname"
    raise TargetPolicyError(f"Could not classify target: {value}")


def require_public_target_confirmation(target: str, kind: str, confirmed: bool) -> str:
    """Warn and require explicit acknowledgement before scanning a public target."""
    if not confirmed:
        raise TargetPolicyError(
            f"Public target detected ({kind}: {target}). Provide explicit confirmation to continue."
        )
    return resolve_target(target, allow_public=True)


def resolve_target(target: str, allow_public: bool = False) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise TargetPolicyError(f"Could not resolve target: {target}") from exc
        if not addresses:
            raise TargetPolicyError(f"Could not resolve target: {target}")
        for candidate in sorted(addresses):
            try:
                return resolve_target(candidate, allow_public=allow_public)
            except TargetPolicyError:
                continue
        raise TargetPolicyError(f"No authorized address found for target: {target}")
    if not allow_public and not (address.is_private or address.is_loopback or address.is_link_local):
        raise TargetPolicyError("Only private, loopback, or link-local IPs are allowed")
    return str(address)
