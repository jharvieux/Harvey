// #1295 — the half of #984 that was specified and never built.
//
// #984 added `req.headers` / `req.cookies` / `next/headers` `headers()` to the shared request-taint
// source block with an explicit guardrail: "route to the review tier where a header is plausibly
// trusted. Do NOT let it introduce free-count FPs." No header-trust logic ever landed, so a header
// was treated exactly like `req.query`. MEASURED 2026-07-30 (semgrep 1.164.0, the repo's own
// ruleset): `headers().get("x-vercel-ip-country")` interpolated into a raw SQL template fired
// `harvey-sql-injection-template` at ERROR + HIGH, and `req.headers["x-real-ip"]` reaching `exec()`
// fired `harvey-command-injection` at ERROR + HIGH — both the free count, the exact outcome the
// guardrail forbade.
//
// WHERE THE LINE IS DRAWN, and why it is not "headers are trusted".
//
// The names below are ones whose canonical producer is the edge that terminates the client
// connection, not the client: Vercel's `x-vercel-ip-*` geolocation set, Cloudflare's `cf-*` set,
// the `x-real-ip` / `x-client-ip` reverse-proxy convention, and the AWS / App Engine / Envoy /
// Netlify / Fly request-identity headers. Whether a client's own copy of one of these survives to
// the application depends on deployment topology that is invisible to a static scan — an app behind the
// platform gets an overwritten value, the same code deployed bare gets the attacker's. That
// irreducible ambiguity is the definition of this repo's review tier ("a benign shape a single-file
// rule does not distinguish, so it is surfaced for triage rather than counted as high-precision"), so
// the finding is DEMOTED, never suppressed, and it states the routing reason.
//
// `x-forwarded-for` / `x-forwarded-host` / `x-forwarded-proto` are deliberately NOT on the list.
// A proxy APPENDS to `X-Forwarded-For` rather than replacing it, and `X-Forwarded-Host` is the
// classic host-header-poisoning vector — the raw value carries attacker input under every topology,
// so those stay free-count.
//
// An arbitrary custom header (`x-tenant-id`, `x-sort-order`, an API key header) also stays
// free-count: a static scan reads a gateway-injected identity header exactly like one the
// client invented, and the failure that matters is the one where nothing injects it. Recorded as an
// explicit decision on #1295 rather than left implicit.

import { readFileSync } from "node:fs";
import type { SemgrepResult } from "./semgrep.js";

const PLATFORM_HEADER =
  /^(?:x-vercel-[a-z0-9-]+|x-appengine-[a-z0-9-]+|x-envoy-[a-z0-9-]+|x-nf-[a-z0-9-]+|cf-connecting-ip|cf-ipcountry|cf-ray|cf-visitor|true-client-ip|x-real-ip|x-client-ip|x-amzn-trace-id|x-amz-cf-id|fly-client-ip|fly-request-id)$/;

// A hyphenated string literal on a line that reads headers — `headers().get("x-real-ip")`,
// `req.headers["x-real-ip"]`, `req.headers.get(…)`, `req.header("X-Real-IP")`, `req.get("X-Real-IP")`.
// The literal only has to be CLASSIFIED, so matching the accessor loosely is safe in the direction
// that matters: a `map.get("some-key")` misread as a header lands in the untrusted bucket, which
// suppresses the demotion rather than causing one.
const HEADER_LINE = /\bheaders?\b|\.\s*(?:get|header)\s*\(/i;
const HEADER_LITERAL = /['"`]([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)['"`]/g;

// The rest of the shared request-taint source block (src/scan/rules/semgrep/base.yml). If any of
// these reaches the same matched span, the span is not header-trust-dependent and keeps its tier.
const OTHER_REQUEST_SOURCE =
  /\b(?:req|request|nextReq|nextRequest|httpReq|incoming)[\w$]*\s*\.\s*(?:query|body|params|cookies)\b|\bsearchParams\b|\bcookies\s*\(\s*\)|\.\s*json\s*\(\s*\)/;

const BINDING = /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/;

interface FileTrust {
  // Identifiers bound on a line whose only request source is a platform-set header.
  platform: Set<string>;
  // Identifiers bound from any other header or request source.
  other: Set<string>;
  platformLiterals: Set<string>;
}

function headerTrustOfSource(src: string): FileTrust {
  const trust: FileTrust = { platform: new Set(), other: new Set(), platformLiterals: new Set() };
  for (const line of src.split("\n")) {
    const headers = HEADER_LINE.test(line)
      ? [...line.matchAll(HEADER_LITERAL)].map((m) => (m[1] ?? "").toLowerCase())
      : [];
    const platformHere = headers.filter((h) => PLATFORM_HEADER.test(h));
    for (const h of platformHere) trust.platformLiterals.add(h);
    const bound = BINDING.exec(line)?.[1];
    if (bound === undefined) continue;
    const untrustedHere = headers.length > platformHere.length || OTHER_REQUEST_SOURCE.test(line);
    if (untrustedHere) trust.other.add(bound);
    else if (platformHere.length > 0) trust.platform.add(bound);
  }
  return trust;
}

function mentions(span: string, name: string): boolean {
  return new RegExp(`\\b${name.replace(/\$/g, "\\$")}\\b`).test(span);
}

function spanIsPlatformHeaderTrusted(span: string, trust: FileTrust): boolean {
  const lower = span.toLowerCase();
  const hasPlatform =
    [...trust.platformLiterals].some((h) => lower.includes(h)) || [...trust.platform].some((n) => mentions(span, n));
  if (!hasPlatform) return false;
  const otherLiteral = HEADER_LINE.test(span)
    ? [...span.matchAll(HEADER_LITERAL)].some((m) => !PLATFORM_HEADER.test((m[1] ?? "").toLowerCase()))
    : false;
  const hasOther =
    otherLiteral || OTHER_REQUEST_SOURCE.test(span) || [...trust.other].some((n) => mentions(span, n));
  return !hasOther;
}

// The findings whose free-count tier rests on trusting a platform-set header. Caches per file
// because a real scan produces many results per path.
export function platformHeaderTrusted(results: readonly SemgrepResult[]): Set<SemgrepResult> {
  const routed = new Set<SemgrepResult>();
  const byPath = new Map<string, { lines: string[]; trust: FileTrust } | null>();
  for (const r of results) {
    const startLine = r.start?.line;
    if (startLine === undefined) continue;
    if (!byPath.has(r.path)) {
      try {
        const src = readFileSync(r.path, "utf8");
        byPath.set(r.path, { lines: src.split("\n"), trust: headerTrustOfSource(src) });
      } catch {
        byPath.set(r.path, null);
      }
    }
    const file = byPath.get(r.path);
    if (file === null || file === undefined) continue;
    const span = file.lines.slice(startLine - 1, r.end?.line ?? startLine).join("\n");
    if (spanIsPlatformHeaderTrusted(span, file.trust)) routed.add(r);
  }
  return routed;
}

export const PLATFORM_HEADER_IMPACT_SUFFIX =
  " Routed to the review tier rather than the free count (#1295): the only request-derived value " +
  "reaching this line is a header whose canonical producer is the platform or reverse proxy in " +
  "front of the app (e.g. x-vercel-ip-*, cf-connecting-ip, x-real-ip). Whether a client can set it " +
  "themselves depends on deployment topology this scan cannot see — confirm the edge overwrites it " +
  "before dismissing, and treat it as live if the app is ever reachable without that edge.";
