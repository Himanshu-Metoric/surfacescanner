import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .cli import normalize_ports
from .policy import ScanPolicy
from .scanner import observations_to_findings, scan
from .risk import risk_label, score_findings
from .targets import TargetPolicyError, classify_target, resolve_target


STYLE = """
<style>
:root { color-scheme: light; --ink:#17212b; --muted:#61707d; --line:#d9e1e7; --paper:#f5f7f8; --accent:#0f766e; --accent-dark:#115e59; --warn:#a16207; --danger:#b42318; }
* { box-sizing:border-box; }
body { margin:0; background:linear-gradient(135deg,#edf5f4 0%,#f8fafb 48%,#eef1f4 100%); color:var(--ink); font:15px/1.5 "Segoe UI", sans-serif; }
main { max-width:1120px; margin:0 auto; padding:42px 22px 64px; }
.masthead { display:flex; justify-content:space-between; gap:20px; align-items:end; margin-bottom:28px; }
h1 { margin:0; font:700 clamp(2rem,5vw,3.8rem)/.98 Georgia, serif; }
.eyebrow { color:var(--accent); font-size:12px; font-weight:700; text-transform:uppercase; margin:0 0 10px; }
.tagline { max-width:340px; color:var(--muted); margin:0; }
.layout { display:grid; grid-template-columns:minmax(280px,360px) 1fr; gap:20px; align-items:start; }
.panel { background:rgba(255,255,255,.92); border:1px solid var(--line); border-radius:8px; box-shadow:0 14px 35px rgba(23,33,43,.07); padding:24px; }
.panel h2 { margin:0 0 18px; font-size:1.2rem; }
label { display:block; font-weight:700; margin:15px 0 7px; }
input[type=text] { width:100%; border:1px solid #b7c4cc; border-radius:5px; padding:11px 12px; color:var(--ink); background:#fff; font:inherit; }
input:focus { outline:3px solid rgba(15,118,110,.18); border-color:var(--accent); }
.hint { color:var(--muted); font-size:13px; margin:6px 0 0; }
.check { display:flex; gap:10px; align-items:flex-start; margin-top:18px; font-weight:600; }
.check input { margin-top:4px; accent-color:var(--accent); }
button { width:100%; border:0; border-radius:5px; background:var(--accent); color:#fff; padding:12px 16px; margin-top:22px; font:700 15px inherit; cursor:pointer; }
button:hover { background:var(--accent-dark); }
button:disabled { opacity:.65; cursor:wait; }
.status { min-height:24px; color:var(--muted); margin:14px 0 0; }
.status.error { color:var(--danger); font-weight:700; }
.empty { display:grid; place-items:center; min-height:330px; color:var(--muted); text-align:center; border:1px dashed #b7c4cc; border-radius:6px; padding:30px; }
.results[hidden] { display:none; }
.summary { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:20px; }
.metric { border-left:4px solid var(--accent); background:var(--paper); padding:13px 14px; }
.metric strong { display:block; font-size:1.35rem; }
.metric span { color:var(--muted); font-size:12px; }
.finding { border-top:1px solid var(--line); padding:15px 0; }
.finding:first-child { border-top:0; }
.finding-title { display:flex; justify-content:space-between; gap:14px; font-weight:700; }
.severity { border-radius:12px; padding:2px 9px; font-size:11px; text-transform:uppercase; white-space:nowrap; background:#e6f4f1; color:var(--accent-dark); }
.severity.high,.severity.critical { background:#fde8e7; color:var(--danger); }
.severity.medium { background:#fff4d6; color:var(--warn); }
.finding p { color:var(--muted); margin:6px 0 0; }
@media (max-width:760px) { main { padding:28px 15px 48px; } .masthead { display:block; } .tagline { margin-top:14px; } .layout { grid-template-columns:1fr; } .summary { grid-template-columns:1fr; } }
</style>
"""


def _page(content: str) -> str:
        return f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Surface Scanner</title>{STYLE}</head><body><main>{content}</main></body></html>"


def _dashboard() -> str:
        return _page("""
        <header class='masthead'><div><p class='eyebrow'>Authorized discovery console</p><h1>Surface Scanner</h1></div><p class='tagline'>Bounded TCP discovery and evidence checks for systems you own or are authorized to assess.</p></header>
        <section class='layout'><form class='panel' id='scan-form'><h2>Start an assessment</h2>
            <label for='target'>Target</label><input id='target' name='target' type='text' value='127.0.0.1' required placeholder='IP address, hostname, or URL'>
            <p class='hint'>Private, loopback, and link-local targets are supported. Public targets require an allowlist and a second confirmation.</p>
            <label for='approved-target'>Approved public target</label><input id='approved-target' name='approved-target' type='text' placeholder='Required only for public targets'>
            <p class='hint'>Enter the exact approved IP, hostname, or URL when assessing a public target.</p>
            <label for='ports'>TCP ports</label><input id='ports' name='ports' type='text' value='22,80,443' required>
            <p class='hint'>Up to 128 ports, from 1 to 65535. No exploit or credential testing is performed.</p>
            <label class='check'><input id='authorized' name='authorized' type='checkbox' required><span>I have authorization to assess this target.</span></label>
            <label class='check'><input id='public-confirm' name='public-confirm' type='checkbox'><span>I understand that a public target requires explicit approval.</span></label>
            <button id='scan-button' type='submit'>Run discovery scan</button><p id='status' class='status' role='status'></p>
        </form><section class='panel'><div id='empty' class='empty'><div><strong>Ready for a target</strong><br>Scan results will appear here with open ports, risk signals, and evidence.</div></div><div id='results' class='results' hidden></div></section></section>
        <script>
        const form = document.getElementById('scan-form'); const button = document.getElementById('scan-button'); const status = document.getElementById('status'); const results = document.getElementById('results'); const empty = document.getElementById('empty');
        const esc = value => String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
        form.addEventListener('submit', async event => { event.preventDefault(); status.className='status'; status.textContent='Checking target policy and scanning...'; button.disabled=true;
            try { const response = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams(new FormData(form))}); const payload = await response.json(); if (!response.ok) throw new Error(payload.error || 'Scan rejected'); render(payload); status.textContent='Scan complete'; }
            catch (error) { status.className='status error'; status.textContent=error.message; results.hidden=true; empty.hidden=false; }
            finally { button.disabled=false; }
        });
        function render(data) { empty.hidden=true; results.hidden=false; const findings=data.findings || []; results.innerHTML=`<div class='summary'><div class='metric'><strong>${esc(data.observations.length)}</strong><span>Open TCP ports</span></div><div class='metric'><strong>${esc(data.risk.toFixed(1))}/10</strong><span>${esc(data.label)} risk</span></div><div class='metric'><strong>${esc(data.engine)}</strong><span>Scan engine</span></div></div><h2>${esc(data.target)}</h2>${findings.length ? findings.map(item => `<article class='finding'><div class='finding-title'><span>${esc(item.title)}</span><span class='severity ${esc(item.severity)}'>${esc(item.severity)}</span></div><p>${esc(item.evidence || 'No additional evidence recorded.')}</p></article>`).join('') : '<p class="hint">No findings detected.</p>'}`; }
        </script>
        """)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if urlparse(self.path).path != "/":
                self.send_error(404)
                return
            self._send(_dashboard())

        def do_POST(self):
            if urlparse(self.path).path != "/api/scan":
                self._send_json({"error": "Not found"}, 404)
                return
            values = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            target = values.get("target", [""])[0].strip()
            try:
                ports = normalize_ports(values.get("ports", ["22,80,443"])[0])
                kind = classify_target(target)
                candidate = resolve_target(target, allow_public=True)
                address = ipaddress.ip_address(candidate)
                is_public = not (address.is_private or address.is_loopback or address.is_link_local)
                approved = values.get("approved-target", [""])[0].strip()
                if is_public and "public-confirm" not in values:
                    raise TargetPolicyError(f"Public target detected ({kind}: {target}). Confirm public target approval to continue.")
                if is_public and approved not in {target, candidate}:
                    raise TargetPolicyError("Public targets require the exact approved target entry.")
                allowlist = frozenset({value for value in (approved, target, candidate) if value}) if is_public else frozenset()
                resolved = ScanPolicy("authorized" in values, allowlist).validate(target)
                observations, engine = scan(resolved, ports)
                findings = observations_to_findings(observations)
                score = score_findings(findings)
                payload = {"target": resolved, "engine": engine, "risk": score, "label": risk_label(score), "observations": [item.__dict__ for item in observations], "findings": [item.__dict__ for item in findings]}
                self._send_json(payload)
            except (TargetPolicyError, ValueError, OSError) as exc:
                self._send_json({"error": str(exc)}, 400)

        def _send(self, body: str, status: int = 200):
            encoded = body.encode()
            self.send_response(status); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)

        def _send_json(self, payload: dict, status: int = 200):
            encoded = json.dumps(payload).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)

        def log_message(self, *_):
            return

    print(f"Web UI: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()