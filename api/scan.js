export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.status(405).json({ error: "Method not allowed" });
    return;
  }

  const backendUrl = process.env.SCANNER_BACKEND_URL;
  if (!backendUrl) {
    response.status(500).json({ error: "SCANNER_BACKEND_URL is not configured" });
    return;
  }

  try {
    const values = typeof request.body === "string" ? JSON.parse(request.body) : (request.body || {});
    const form = new URLSearchParams();
    for (const field of ["target", "ports", "approved-target"]) {
      if (values[field]) form.set(field, String(values[field]));
    }
    if (values.authorized) form.set("authorized", "on");
    if (values["public-confirm"]) form.set("public-confirm", "on");

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 55000);
    const endpoint = `${backendUrl.replace(/\/$/, "")}/api/scan`;
    const upstream = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
      signal: controller.signal
    });
    clearTimeout(timeout);

    const payload = await upstream.json();
    response.status(upstream.status).json(payload);
  } catch (error) {
    response.status(error.name === "AbortError" ? 504 : 502).json({
      error: error.name === "AbortError" ? "Scanner backend timed out" : "Scanner backend is unavailable"
    });
  }
}
