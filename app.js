const form = document.getElementById("scan-form");
const button = document.getElementById("scan-button");
const status = document.getElementById("status");
const results = document.getElementById("results");
const empty = document.getElementById("empty");

const escapeHtml = (value) => String(value ?? "").replace(/[&<>\"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
}[character]));

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.className = "status";
  status.textContent = "Checking authorization and scanning...";
  button.disabled = true;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Scan rejected");
    render(payload);
    status.textContent = "Scan complete";
  } catch (error) {
    status.className = "status error";
    status.textContent = error.message;
    results.hidden = true;
    empty.hidden = false;
  } finally {
    button.disabled = false;
  }
});

function render(data) {
  const findings = data.findings || [];
  empty.hidden = true;
  results.hidden = false;
  results.innerHTML = `<div class="summary">
    <div class="metric"><strong>${escapeHtml(data.observations?.length || 0)}</strong><span>Open TCP ports</span></div>
    <div class="metric"><strong>${escapeHtml(Number(data.risk || 0).toFixed(1))}/10</strong><span>${escapeHtml(data.label)} risk</span></div>
    <div class="metric"><strong>${escapeHtml(data.engine)}</strong><span>Scan engine</span></div>
  </div>
  <h2>${escapeHtml(data.target)}</h2>
  ${findings.length ? findings.map((item) => `<article class="finding"><div class="finding-title"><span>${escapeHtml(item.title)}</span><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span></div><p>${escapeHtml(item.evidence || "No additional evidence recorded.")}</p></article>`).join("") : '<p class="hint">No findings detected.</p>'}`;
}
