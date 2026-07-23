import { NextResponse } from "next/server";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const esc = (s: string) => s.replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c] as string);

async function sendEmail(apiKey: string, body: Record<string, unknown>, idempotencyKey: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey.slice(0, 256),
    },
    body: JSON.stringify(body),
  });
}

export async function POST(req: Request) {
  let payload: { email?: string; repo?: string; context?: string };
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  const email = String(payload.email ?? "").trim();
  const repo = String(payload.repo ?? "").trim();
  const context = String(payload.context ?? "").trim();

  if (!EMAIL_RE.test(email)) return NextResponse.json({ error: "Please enter a valid email." }, { status: 400 });
  if (!repo) return NextResponse.json({ error: "Please tell us how to access the repo." }, { status: 400 });

  const apiKey = process.env.RESEND_API_KEY;
  const notifyTo = process.env.SCAN_NOTIFY_TO;
  // Until harvey-qa.com is verified in Resend, the sandbox sender only delivers to the
  // Resend account owner's email (so the operator notification below still works).
  const from = process.env.RESEND_FROM ?? "Harvey <onboarding@resend.dev>";

  if (!apiKey || !notifyTo) {
    console.error("scan intake not configured: RESEND_API_KEY and/or SCAN_NOTIFY_TO missing");
    return NextResponse.json({ error: "Scan intake isn't set up yet — please email us directly." }, { status: 503 });
  }

  // Operator notification — this IS the lead capture; fail the request if it doesn't send.
  const notify = await sendEmail(
    apiKey,
    {
      from,
      to: [notifyTo],
      reply_to: email,
      subject: `New free-scan request — ${email}`,
      html:
        `<h2>New free-scan request</h2>` +
        `<p><b>Email:</b> ${esc(email)}</p>` +
        `<p><b>Repo access:</b> ${esc(repo)}</p>` +
        (context ? `<p><b>Context:</b> ${esc(context)}</p>` : ""),
    },
    `scan-request/${email}`,
  );

  if (!notify.ok) {
    console.error("resend notify failed", notify.status, await notify.text().catch(() => ""));
    return NextResponse.json({ error: "Something went wrong sending your request — please email us directly." }, { status: 502 });
  }

  // Confirmation to the requester — best-effort. Fails in the resend.dev sandbox until the
  // domain is verified, so never fail the request on it.
  try {
    await sendEmail(
      apiKey,
      {
        from,
        to: [email],
        subject: "Your Harvey free scan is on the way",
        html:
          `<p>Thanks — we've got your request and we'll send your ten-module readiness report within one business day.</p>` +
          `<p>Nothing to do on your end: we only need read access to the code you pointed us at — no database, no credentials.</p>` +
          `<p>— Harvey · harvey-qa.com</p>`,
      },
      `scan-confirm/${email}`,
    );
  } catch (err) {
    console.error("resend confirmation failed (non-fatal)", err);
  }

  return NextResponse.json({ ok: true });
}
