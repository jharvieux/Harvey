// Vercel serverless function: receives the intake form as JSON, emails it to
// the operator via Resend. No secrets are accepted here by design — the form
// has no credential fields, and this function stores nothing.

const FIELD_LABELS = [
  ["name", "Name"],
  ["email", "Email"],
  ["company", "Company"],
  ["role", "Role"],
  ["repo_url", "Repository"],
  ["app_url", "Production URL"],
  ["hosting", "Hosting"],
  ["description", "App description"],
  ["tenancy_model", "Tenancy model"],
  ["tenant_link", "Tenant link mechanism"],
  ["auth_provider", "Auth provider"],
  ["enforcement", "Authorization enforced via"],
  ["roles", "Roles & intent"],
  ["data_types", "Regulated data"],
  ["compliance", "Compliance regimes"],
  ["staging", "Staging environment"],
  ["integrations", "Integrations"],
  ["reason", "What prompted the audit"],
  ["timeline", "Timeline"],
  ["tier", "Tier interest"],
  ["access_confirm", "Access confirmations"],
];

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "method not allowed" });
    return;
  }

  const data = req.body ?? {};

  // Honeypot: bots fill the hidden field; pretend success and drop it.
  if (data.website) {
    res.status(200).json({ ok: true });
    return;
  }

  const missing = ["name", "email", "repo_url"].filter(
    (key) => !String(data[key] ?? "").trim(),
  );
  if (missing.length) {
    res.status(400).json({ error: `missing required fields: ${missing.join(", ")}` });
    return;
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: "intake mailer is not configured" });
    return;
  }

  const lines = FIELD_LABELS.map(([key, label]) => {
    const value = String(data[key] ?? "").trim();
    return `${label}: ${value || "—"}`;
  });

  const send = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: process.env.INTAKE_FROM ?? "Harvey Intake <onboarding@resend.dev>",
      to: [process.env.INTAKE_TO ?? "jharvieux@gmail.com"],
      reply_to: String(data.email),
      subject: `Harvey intake — ${String(data.company || data.name).trim()}`,
      // Plain text on purpose: form input is untrusted, so no HTML rendering.
      text: lines.join("\n"),
    }),
  });

  if (!send.ok) {
    console.error("resend error", send.status, await send.text());
    res.status(502).json({ error: "could not deliver intake email" });
    return;
  }

  res.status(200).json({ ok: true });
}
