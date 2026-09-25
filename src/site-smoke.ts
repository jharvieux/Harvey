// Evaluation logic for the marketing-site smoke check (#1308). Kept apart from the CLI so the
// verdict arithmetic is testable offline, in `pnpm verify`, without reaching the network.
//
// What this exists to catch, in the words of the outage it was written for: on 2026-07-28 the live
// site had been serving a build from 2026-07-22 for six days. Nine of the ten routes the repo
// declares in site/app/sitemap.ts returned 404, /api/scan returned 503 because its Resend env vars
// had never been set, and NOTHING reported any of it — the failure was only visible to a prospect
// who filled in the form and read the error. Every check below is one of those symptoms.

type CheckStatus = "pass" | "fail";

interface SmokeCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}

/** A route the repo declares (site/app/sitemap.ts) and the status the deployment answered with. */
export interface RouteProbe {
  path: string;
  status: number;
}

export interface RedirectDeclaration {
  source: string;
  destination: string;
}

interface RedirectProbe extends RouteProbe {
  destination: string;
  location: string | null;
  finalUrl?: string;
  finalStatus?: number;
  error?: string;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function probeRedirects(base: string, declarations: RedirectDeclaration[]): Promise<RedirectProbe[]> {
  return Promise.all(declarations.map(async ({ source, destination }) => {
    const result: RedirectProbe = { path: source, destination, status: 0, location: null };
    try {
      const initial = new URL(source, base);
      const expected = new URL(destination, base);
      const first = await fetch(initial, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
      result.status = first.status;
      result.location = first.headers.get("location");
      if (!REDIRECT_STATUSES.has(first.status)) throw new Error(`source answered ${first.status}, not a redirect`);
      if (!result.location) throw new Error("source has no Location header");
      let current = new URL(result.location, initial);
      if (current.href !== expected.href) throw new Error(`Location ${current.href} differs from declared ${expected.href}`);
      const requestIdentity = (url: URL): string => { const copy = new URL(url); copy.hash = ""; return copy.href; };
      const seen = new Set([requestIdentity(initial)]);
      // Reaching this bound is a failed assessment, never evidence of a healthy destination.
      for (let hop = 0; hop < 5; hop++) {
        if (!["http:", "https:"].includes(current.protocol) || current.username || current.password || current.origin !== expected.origin) throw new Error(`redirect chain leaves declared destination origin at ${current.href}`);
        if (seen.has(requestIdentity(current))) throw new Error(`redirect loop reaches ${current.href}`);
        seen.add(requestIdentity(current));
        result.finalUrl = current.href;
        const response = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
        result.finalStatus = response.status;
        if (response.status === 200) return result;
        if (!REDIRECT_STATUSES.has(response.status)) throw new Error(`destination ${current.href} answered ${response.status}`);
        const location = response.headers.get("location");
        if (!location) throw new Error(`destination ${current.href} redirected without Location`);
        current = new URL(location, current);
      }
      throw new Error("redirect chain exceeds five destination requests");
    } catch (error) {
      result.error = error instanceof Error ? error.message : String(error);
      return result;
    }
  }));
}

export interface SmokeInput {
  /** Paths declared by the repo's sitemap source — the contract the deployment must satisfy. */
  declared: string[];
  /** Paths the DEPLOYED /sitemap.xml advertises. */
  served: string[];
  routes: RouteProbe[];
  /**
   * Redirect sources the repo declares (site/next.config.mjs), probed WITHOUT following. A redirect
   * is a live path the sitemap does not list, so the route check above never probes one — which is
   * how /intake, the symptom #1308 was filed for, 404ed in production while every other check here
   * stayed green.
   */
  redirects: RedirectProbe[];
  /**
   * GET /api/scan — the readiness probe. `configured: null` = the deployment has no GET handler.
   * `sandboxSender: null` = this build predates the sender probe, so which sender is in force is
   * unmeasured — reported as its own state rather than folded into either answer.
   */
  readiness: { status: number; configured: boolean | null; sandboxSender: boolean | null };
  /** POST /api/scan with a deliberately invalid body; the handler must reject it with a 400. */
  validation: { status: number };
}

function sorted(paths: string[]): string[] {
  return [...paths].sort();
}

export function evaluateSmoke(input: SmokeInput): SmokeCheck[] {
  const checks: SmokeCheck[] = [];

  const broken = input.routes.filter((r) => r.status !== 200);
  checks.push({
    name: "declared routes serve 200",
    status: broken.length === 0 ? "pass" : "fail",
    detail:
      broken.length === 0
        ? `all ${input.routes.length} declared routes returned 200`
        : `${broken.length} of ${input.routes.length} did not: ${broken.map((r) => `${r.path} → ${r.status}`).join(", ")}`,
  });

  // The stale-deploy detector. A route probe answers only "is this path 200 today", which reads
  // the same whether the page was deleted on purpose or the deployment predates it. The deployed
  // sitemap separates them, being generated from the same source the declared list is read from.
  const missing = sorted(input.declared.filter((p) => !input.served.includes(p)));
  const extra = sorted(input.served.filter((p) => !input.declared.includes(p)));
  checks.push({
    name: "deployed sitemap matches the repo's",
    status: missing.length === 0 && extra.length === 0 ? "pass" : "fail",
    detail:
      missing.length === 0 && extra.length === 0
        ? `${input.declared.length} paths, identical`
        : [
            missing.length > 0 ? `declared but NOT served (deployment is behind main): ${missing.join(", ")}` : "",
            extra.length > 0 ? `served but no longer declared: ${extra.join(", ")}` : "",
          ]
            .filter(Boolean)
            .join("; "),
  });

  // A redirect that stops redirecting is indistinguishable, to every other check here, from one
  // that was never declared: the sitemap does not list it and no page file backs it. Only the
  // deployment's own answer separates them, so ask for it.
  const deadRedirects = input.redirects.filter((r) => !REDIRECT_STATUSES.has(r.status) || !r.location || r.finalStatus !== 200 || r.error);
  checks.push({
    name: "declared redirects still redirect",
    status: deadRedirects.length === 0 ? "pass" : "fail",
    detail:
      input.redirects.length === 0
        ? "the repo declares no redirects"
        : deadRedirects.length === 0
          ? `all ${input.redirects.length} declared redirects reached healthy destinations: ${input.redirects.map(r => `${r.path} → ${r.destination} (${r.finalStatus})`).join(", ")}`
          : `${deadRedirects.length} of ${input.redirects.length} did NOT redirect: ${deadRedirects
              .map((r) => `${r.path} → ${r.status}; declared ${r.destination}: ${r.error ?? `destination was not confirmed healthy (Location ${r.location ?? "missing"}, terminal ${r.finalStatus ?? "unmeasured"})`}`)
              .join(", ")} — a visitor following that path meets a dead end (#1308)`,
  });

  checks.push({
    name: "/api/scan is configured (lead capture is live)",
    status: input.readiness.configured === true ? "pass" : "fail",
    detail:
      input.readiness.configured === true
        ? "readiness probe reports configured"
        : input.readiness.configured === null
          ? `GET /api/scan → ${input.readiness.status} with no readiness body — the deployment predates the readiness probe, so whether leads are being captured is UNKNOWN`
          : `readiness probe reports NOT configured (HTTP ${input.readiness.status}) — RESEND_API_KEY and/or SCAN_NOTIFY_TO are unset on the deployment; every lead submitted right now is rejected`,
  });

  // The operator notification is the lead capture and the checks above cover it. This covers the
  // other half: on the sandbox sender the prospect's confirmation is dropped and the request still
  // answers 200, so the funnel reads healthy from every angle except the prospect's.
  checks.push({
    name: "requester confirmations send from a verified domain",
    status: input.readiness.sandboxSender === false ? "pass" : "fail",
    detail:
      input.readiness.sandboxSender === false
        ? "RESEND_FROM is a non-sandbox sender"
        : input.readiness.sandboxSender === null
          ? "the deployment predates the sender probe, so whether requester confirmations are delivered at all is UNKNOWN — redeploy to answer it"
          : "RESEND_FROM is unset or still the resend.dev sandbox sender — Resend delivers those only to the account owner, so every prospect's confirmation is silently dropped; verify harvey-qa.com in Resend and set RESEND_FROM",
  });

  checks.push({
    name: "/api/scan rejects an invalid submission with 400",
    status: input.validation.status === 400 ? "pass" : "fail",
    detail:
      input.validation.status === 400
        ? "handler is live and validating"
        : `expected 400, got ${input.validation.status}`,
  });

  return checks;
}

export function smokeFailed(checks: SmokeCheck[]): boolean {
  return checks.some((c) => c.status === "fail");
}
