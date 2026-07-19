// #578 — security-header presence check over a hosting platform's config, for apps that set
// response headers OUTSIDE next.config.js. The harvey-missing-hsts/frame-options/nosniff semgrep
// rules (headers.yml) only match a next.config.js `headers()` route object; a Vite/no-code SPA sets
// its headers in a Netlify `public/_headers` file, `netlify.toml`, or `vercel.json` instead. This is
// a config-presence check (sibling of checkMissingCsp): if one of those files exists (the app IS
// managing headers there) but a given security header is absent from all of them, report it. Review
// tier — the header can legitimately be set at a CDN/proxy layer this scan can't see, same caveat as
// checkMissingCsp.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

const HOSTING_CONFIG_FILES = ["public/_headers", "_headers", "netlify.toml", "vercel.json"];

interface HeaderCheck {
  id: string;
  header: string;
  // Present if EITHER token appears (X-Frame-Options is satisfiable by a CSP frame-ancestors directive).
  tokens: RegExp;
  severity: "Medium" | "Low";
  impact: string;
  fix: string;
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    id: "hsts",
    header: "Strict-Transport-Security",
    tokens: /strict-transport-security/i,
    severity: "Medium",
    impact: "Without HSTS a user's first request (or any downgraded request) can be intercepted over plain HTTP before the redirect to HTTPS.",
    fix: "Add a Strict-Transport-Security header (e.g. `max-age=63072000; includeSubDomains`) in the hosting config.",
  },
  {
    id: "frame-options",
    header: "X-Frame-Options",
    tokens: /x-frame-options|frame-ancestors/i,
    severity: "Medium",
    impact: "Without X-Frame-Options (or a CSP frame-ancestors directive) the page can be framed by any site and used for clickjacking.",
    fix: "Add `X-Frame-Options: DENY` (or a CSP `frame-ancestors 'none'` directive) in the hosting config.",
  },
  {
    id: "nosniff",
    header: "X-Content-Type-Options",
    tokens: /x-content-type-options/i,
    severity: "Low",
    impact: "Without X-Content-Type-Options: nosniff a browser may MIME-sniff a response into an executable content type.",
    fix: "Add `X-Content-Type-Options: nosniff` in the hosting config.",
  },
];

export function checkHostingConfigHeaders(dir: string): Finding[] {
  const present = HOSTING_CONFIG_FILES.map((f) => ({ rel: f, path: join(dir, f) })).filter((f) => existsSync(f.path));
  if (present.length === 0) return [];

  const combined = present.map((f) => readFileSync(f.path, "utf8")).join("\n");
  const where = present.map((f) => f.rel).join(", ");

  return HEADER_CHECKS.filter((c) => !c.tokens.test(combined)).map((c) =>
    mechanicalFinding({
      id: `HOSTING-HEADER-${c.id}`,
      title: `Hosting config sets response headers but not ${c.header}`,
      severity: c.severity,
      category: "Next.js/web footgun",
      taxonomy: "Missing security headers",
      location: present[0]!.rel,
      evidence: `No ${c.header} found in the hosting header config (${where}).`,
      impact: c.impact,
      fix: c.fix,
      precisionTier: "review",
    }),
  );
}
