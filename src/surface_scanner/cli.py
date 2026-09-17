import argparse

from .policy import ScanPolicy, load_allowlist
from .local import scan_local_endpoints
from .report import write_csv, write_json, write_pdf, write_text
from .risk import risk_label, score_findings
from .scanner import observations_to_findings, scan
from .scheduler import run_schedule
from .targets import TargetPolicyError, classify_target, require_public_target_confirmation, resolve_target


def normalize_ports(ports: str | list[int] | tuple[int, ...] | None) -> list[int]:
    """Normalize a port specification into a deduplicated, validated list."""
    if ports is None:
        raise ValueError("ports are required")

    if isinstance(ports, str):
        raw_values = ports.split(",")
    else:
        raw_values = [str(item) for item in ports]

    normalized: list[int] = []
    for value in raw_values:
        text = str(value).strip()
        if not text:
            raise ValueError("ports must not contain empty values")
        try:
            port = int(text)
        except ValueError as exc:
            raise ValueError(f"ports must be integers between 1 and 65535; got {text!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError("ports must be integers between 1 and 65535")
        normalized.append(port)

    unique = sorted(set(normalized))
    if not unique:
        raise ValueError("ports must contain at least one valid port")
    if len(unique) > 128:
        raise ValueError("ports must contain 1-128 values from 1 to 65535")
    return unique


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized discovery and enumeration only. No credential harvesting, brute-force, or exploitation."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a bounded TCP connect scan")
    scan.add_argument("target")
    scan.add_argument("--i-have-authorization", action="store_true", required=True)
    scan.add_argument("--ports", default="22,80,443", help="Comma-separated ports, max 128")
    scan.add_argument("--timeout", type=float, default=0.5)
    scan.add_argument("--csv", dest="csv_path")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--text", dest="text_path")
    scan.add_argument("--pdf", dest="pdf_path")
    scan.add_argument("--no-nmap", action="store_true")
    scan.add_argument("--authorized-targets", help="File containing explicitly approved IPs/hostnames")
    web = subparsers.add_parser("web", help="Start the local web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    schedule = subparsers.add_parser("schedule", help="Run repeated authorized scans")
    schedule.add_argument("target")
    schedule.add_argument("--i-have-authorization", action="store_true", required=True)
    schedule.add_argument("--ports", default="22,80,443")
    schedule.add_argument("--interval", type=int, default=3600)
    schedule.add_argument("--runs", type=int, default=1)
    schedule.add_argument("--authorized-targets", help="File containing explicitly approved IPs/hostnames")
    subparsers.add_parser("local", help="Inventory local listening TCP endpoints")
    return parser


def _prompt_target_details(target: str) -> tuple[str, bool]:
    """Ask the user to specify the target kind and confirm public targets before scanning."""
    kind = classify_target(target)
    if kind in {"ip", "hostname", "url"}:
        try:
            resolved = resolve_target(target, allow_public=True)
            address = __import__("ipaddress").ip_address(resolved)
            if not (address.is_private or address.is_loopback or address.is_link_local):
                print(f"WARNING: public target detected ({kind}: {target})")
                response = input("Type 'ALLOW PUBLIC TARGET' to proceed with this public target: ").strip()
                if response != "ALLOW PUBLIC TARGET":
                    raise TargetPolicyError("Public target scan cancelled by user.")
        except ValueError:
            pass
    return target, True


def main() -> int:
    from .web import serve

    args = build_parser().parse_args()
    if args.command == "web":
        serve(args.host, args.port); return 0
    if args.command == "local":
        observations = scan_local_endpoints()
        print(f"Local listening TCP endpoints: {len(observations)}")
        for item in observations:
            print(f"- {item.port}: {item.service} ({item.evidence})")
        return 0
    if args.command == "schedule":
        try:
            ports = normalize_ports(args.ports)
            interval = max(1, int(args.interval))
            runs = max(1, int(args.runs))
            _prompt_target_details(args.target)
            run_schedule(args.target, ports, ScanPolicy(args.i_have_authorization, load_allowlist(args.authorized_targets)), interval, runs)
            return 0
        except (TargetPolicyError, ValueError) as exc:
            print(f"Error: {exc}"); return 2
    try:
        _prompt_target_details(args.target)
        target = ScanPolicy(args.i_have_authorization, load_allowlist(args.authorized_targets)).validate(args.target)
        ports = normalize_ports(args.ports)
    except (TargetPolicyError, ValueError) as exc:
        print(f"Error: {exc}")
        return 2
    observations, engine = scan(target, ports, timeout=max(0.1, min(args.timeout, 5.0)), prefer_nmap=not args.no_nmap)
    findings = observations_to_findings(observations)
    score = score_findings(findings)
    if args.csv_path:
        write_csv(args.csv_path, findings)
    if args.json_path:
        write_json(args.json_path, observations, findings, score)
    if args.text_path:
        write_text(args.text_path, target, observations, findings, score)
    if args.pdf_path:
        write_pdf(args.pdf_path, target, observations, findings, score)
    print(f"Target: {target}; engine: {engine}; open TCP ports: {len(observations)}; risk: {score}/10 ({risk_label(score)})")
    return 0
