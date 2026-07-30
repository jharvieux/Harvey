import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const esc = (s: string) => s.replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c] as string);

// The sample-report PDF (#742): synthetic "Larkspur" engagement rendered once via
// report-template/render.mjs from report-template/sample-findings.json and committed as a static
// asset — the marketing sample doesn't need per-request Chromium rendering. Read once per cold
// start, not per request.
const SAMPLE_PDF_PATH = path.join(process.cwd(), "public", "harvey-sample-report.pdf");
let samplePdfBase64: string | null = null;
function loadSamplePdfBase64(): string {
  if (samplePdfBase64 === null) samplePdfBase64 = fs.readFileSync(SAMPLE_PDF_PATH).toString("base64");
  return samplePdfBase64;
}

// Best-effort in-memory rate limit: caps requests per IP per window. Resets on cold start
// and isn't shared across serverless instances, but stops trivial floods of a public form.
const RATE_LIMIT = 5;
const WINDOW_MS = 60_000;
const hits = new Map<string, { count: number; resetAt: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const rec = hits.get(ip);
  if (!rec || now > rec.resetAt) {
    hits.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  rec.count += 1;
  return rec.count > RATE_LIMIT;
}

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

// The requester confirmations are best-effort — they must never fail the lead capture, which is the
// operator notification. But "best-effort" was reading as "unobservable": a Resend REJECTION is an
// HTTP 4xx, not a thrown error, so the try/catch these calls used to sit in never saw one. Every
// confirmation could have been bouncing (which is exactly what the resend.dev sandbox sender does
// for anyone but the account owner) and the logs would have been empty. Swallow the failure, not
// the evidence.
async function sendBestEffort(
  label: string,
  apiKey: string,
  body: Record<string, unknown>,
  idempotencyKey: string,
): Promise<void> {
  try {
    const res = await sendEmail(apiKey, body, idempotencyKey);
    if (!res.ok) console.error(`resend ${label} failed (non-fatal)`, res.status, await res.text().catch(() => ""));
  } catch (err) {
    console.error(`resend ${label} failed (non-fatal)`, err);
  }
}

// Readiness probe. The intake sat unconfigured in production for five days (#1308) because the
// only way to learn it was dead was to submit a lead and read the error — i.e. to be the prospect
// who got dropped. This makes that state machine-readable from outside, so a monitor can see it
// (src/cli/site-smoke.ts). Booleans only: never echo an env VALUE here.
export async function GET() {
  const ready = Boolean(process.env.RESEND_API_KEY && process.env.SCAN_NOTIFY_TO);
  // `configured` covers the OPERATOR half of the lead path. The requester half has its own silent
  // failure mode: on Resend's sandbox sender, delivery is restricted to the Resend account owner,
  // so the form returns 200, the operator gets their notification, and the prospect's confirmation
  // is dropped with nothing anywhere reporting it. Report which sender is in force as a BOOLEAN —
  // still never an env VALUE — so that state is answerable from outside instead of by asking the
  // Resend dashboard.
  const from = process.env.RESEND_FROM;
  return NextResponse.json(
    { service: "scan-intake", configured: ready, sandboxSender: !from || from.includes("resend.dev") },
    { status: ready ? 200 : 503 },
  );
}

export async function POST(req: Request) {
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "unknown";
  if (rateLimited(ip)) {
    return NextResponse.json({ error: "Too many requests — please wait a minute and try again." }, { status: 429 });
  }

  let payload: { kind?: string; email?: string; repo?: string; context?: string; summary?: string };
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  const email = String(payload.email ?? "").trim();
  if (!EMAIL_RE.test(email)) return NextResponse.json({ error: "Please enter a valid email." }, { status: 400 });

  const apiKey = process.env.RESEND_API_KEY;
  const notifyTo = process.env.SCAN_NOTIFY_TO;
  // Until harvey-qa.com is verified in Resend, the sandbox sender only delivers to the
  // Resend account owner's email (so the operator notification below still works).
  const from = process.env.RESEND_FROM ?? "Harvey <onboarding@resend.dev>";

  if (!apiKey || !notifyTo) {
    console.error("scan intake not configured: RESEND_API_KEY and/or SCAN_NOTIFY_TO missing");
    return NextResponse.json({ error: "Scan intake isn't set up yet — please email us directly." }, { status: 503 });
  }

  // RLS-checker lead (#749): opt-in follow-up from the free browser checker. No repo — the user
  // shares only their email and a coarse, count-only summary; the project URL and anon key never
  // leave their browser. (The write-attempt probe is deferred to #888.)
  if (payload.kind === "checker-lead") {
    const summary = String(payload.summary ?? "").trim().slice(0, 500);
    const leadNotify = await sendEmail(
      apiKey,
      {
        from,
        to: [notifyTo],
        reply_to: email,
        subject: `New RLS-checker lead — ${email}`,
        html:
          `<h2>New RLS-checker lead</h2>` +
          `<p><b>Email:</b> ${esc(email)}</p>` +
          `<p><b>Checker summary (coarse, user-shared):</b> ${summary ? esc(summary) : "(none provided)"}</p>` +
          `<p>The checker never sends the project URL or anon key — follow up to offer a closer look.</p>`,
      },
      `checker-lead/${email}`,
    );
    if (!leadNotify.ok) {
      console.error("resend checker-lead notify failed", leadNotify.status, await leadNotify.text().catch(() => ""));
      return NextResponse.json({ error: "Something went wrong — please email us directly." }, { status: 502 });
    }
    await sendBestEffort(
      "checker-lead confirmation",
      apiKey,
      {
        from,
        to: [email],
        subject: "Harvey — your RLS check, a closer look",
        html:
          `<p>Thanks for running the free RLS checker. We've got your note and we'll follow up with a closer look.</p>` +
          `<p>Just so it's clear: we only received what you typed — your Supabase URL and anon key stayed in your browser and were never sent to us.</p>` +
          `<p>— Harvey · harvey-qa.com</p>`,
      },
      `checker-lead-confirm/${email}`,
    );
    return NextResponse.json({ ok: true });
  }

  // Sample-report PDF request (#742): the visible download is email-gated rather than a public
  // static link, so a request always leaves a lead. The PDF itself IS what was asked for, so —
  // unlike the best-effort confirmations above — sending it is the leg that gates the response;
  // the operator lead notification is the auxiliary one here.
  if (payload.kind === "sample-report-pdf") {
    let pdfBase64: string;
    try {
      pdfBase64 = loadSamplePdfBase64();
    } catch (err) {
      console.error("sample-report PDF missing on disk", err);
      return NextResponse.json({ error: "Something went wrong — please email us directly." }, { status: 500 });
    }
    const deliver = await sendEmail(
      apiKey,
      {
        from,
        to: [email],
        subject: "Your Harvey sample report",
        html:
          `<p>Here's the sample Harvey report — a full ten-module readiness audit on a fictional booking app,` +
          ` shown with synthetic data so you can see the shape of what a real engagement delivers.</p>` +
          `<p>Want this on your own codebase? <a href="https://harvey-qa.com/#scan">Run the free scan</a>.</p>` +
          `<p>— Harvey · harvey-qa.com</p>`,
        attachments: [{ filename: "harvey-sample-report.pdf", content: pdfBase64 }],
      },
      `sample-report-pdf/${email}`,
    );
    if (!deliver.ok) {
      console.error("resend sample-report-pdf delivery failed", deliver.status, await deliver.text().catch(() => ""));
      return NextResponse.json({ error: "Something went wrong sending the PDF — please email us directly." }, { status: 502 });
    }
    await sendBestEffort(
      "sample-report-pdf lead",
      apiKey,
      {
        from,
        to: [notifyTo],
        reply_to: email,
        subject: `Sample-report PDF requested — ${email}`,
        html: `<h2>Sample-report PDF requested</h2><p><b>Email:</b> ${esc(email)}</p>`,
      },
      `sample-report-pdf-lead/${email}`,
    );
    return NextResponse.json({ ok: true });
  }

  const repo = String(payload.repo ?? "").trim();
  const context = String(payload.context ?? "").trim();
  if (!repo) return NextResponse.json({ error: "Please tell us how to access the repo." }, { status: 400 });

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
  await sendBestEffort(
    "scan confirmation",
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

  return NextResponse.json({ ok: true });
}
