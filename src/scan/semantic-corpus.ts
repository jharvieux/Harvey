// M1 SEMANTIC-tier recall gate (#870). The mechanical tier has a scored gate
// (cli/validate-calibration.ts); the paid semantic pass (`/vuln-scan --extra briefs/scan-extras.txt`
// → `/triage --fp-rules briefs/fp-rules.txt`) had none — so a prompt-brief edit, a model change or an
// fp-rules tweak could degrade the tier that carries the product and nothing would fail.
//
// This module holds the ANSWER KEY for the four targets whose semantic tier was measured against a
// published key, plus the scorer. The gate itself is cli/validate-semantic.ts: it reads the
// `M1.pass.json` a semantic pass leaves via `pnpm record-pass` (docs/design/audit-pass-artifacts.md)
// and scores its findings against the key here.
//
// WHAT THIS GATE IS AND IS NOT
//   - It scores a REAL pass artifact. It never runs the LLM and never asserts a pass happened: a
//     target with no artifact is a NOT-SCORED row carrying its reason, never a silent drop and
//     never a zero (a zero would read as "the tier found nothing", the inverse of "nobody looked").
//   - `recordedCaught` per target is the semantic tally its measurement doc RECORDED on
//     `recordedOn`. It is a claim about the past — the regression floor this gate re-measures
//     against, not evidence of present capability. Only a run of this tool produces a present
//     number (CLAUDE.md, "measure, don't recall").
//   - Matching is location + keyword, the same shape calibration.ts uses. It is deliberately
//     generous: one broad finding can satisfy two adjacent entries (three of supatest's nine sit in
//     one migration file). scoreSemanticPass reports how many findings did that, so the caveat
//     travels with the number instead of living in a comment nobody reads.

import type { Finding } from "../findings.js";
import { MAX_PASS_AGE_MS, type PassArtifact } from "../audit-pass-artifact.js";

export interface SemanticEntry {
  id: string;
  kind: "positive" | "negative";
  cls: string;
  // Any-of: the finding's location must contain one of these (case-insensitive substring), which is
  // what pins a finding to the planted bug's file rather than to its wording alone.
  locations: string[];
  // Any-of: at least one must appear in the finding's id/title/taxonomy/evidence/location. These
  // name the MECHANISM, so a right-file/wrong-mechanism finding (the "partial" the measurement docs
  // record) does not score as a catch.
  match: string[];
  note: string;
}

export interface SemanticTarget {
  slug: string;
  repo: string; // owner/name on GitHub
  ref: string; // branch/tag the answer key describes — SuperRedHat's key is the `vulnerable` branch
  scope?: string; // subdirectory the pass reviews, when the key covers only part of the repo
  source: string; // the measurement doc this key was transcribed from
  recordedOn: string; // the date that doc recorded its semantic tally
  // The semantic-tier catch count that doc recorded. The regression floor, labelled as recorded.
  recordedCaught: number;
  entries: SemanticEntry[];
}

// ---------------------------------------------------------------------------------------------
// The answer keys. Transcribed from the per-finding tables of the measurement docs named in
// `source` — the same keys the mechanical tier was scored against, so the two tiers are comparable.
// ---------------------------------------------------------------------------------------------

const nocodeRescue: SemanticTarget = {
  slug: "nocode-rescue",
  repo: "yagaMI-Reverse/nocode-rescue",
  ref: "main",
  scope: "before",
  source: "docs/design/nocode-rescue-recall-measurement.md",
  recordedOn: "2026-07-18",
  recordedCaught: 8,
  entries: [
    { id: "NR-1", kind: "positive", cls: "service-role key hardcoded in the browser Supabase client", locations: ["src/lib/supabaseClient.ts", ".env"], match: ["service_role", "service-role", "service role"], note: "Mechanically missed at the re-score (the key is a JWT literal passed to createClient); semantic carried it." },
    { id: "NR-2", kind: "positive", cls: "OpenAI key shipped to the browser + dangerouslyAllowBrowser", locations: ["src/lib/ai.ts", ".env"], match: ["dangerouslyallowbrowser", "openai", "vite_openai"], note: "harvey-dangerously-allow-browser closed this mechanically (#565/#589); semantic also catches it." },
    { id: "NR-3", kind: "positive", cls: "RLS off on tickets/profiles/workspaces", locations: ["schema.sql"], match: ["rls", "row level security", "row-level security"], note: "Mechanically blocked by the unqualified `create table` regex (residual gap B); semantic + dynamic carry it." },
    { id: "NR-4", kind: "positive", cls: "authentication enforced only in the client", locations: ["src/pages/Dashboard.tsx"], match: ["authentication", "client-only auth", "client-side auth"], note: "Mechanical lands on the line via an M9 SSR note — wrong mechanism, not a catch." },
    { id: "NR-5", kind: "positive", cls: "authorization decided from localStorage.role", locations: ["src/pages/Dashboard.tsx"], match: ["authorization", "localstorage", "admin"], note: "AUTH-client-side-authz closed this mechanically (#576)." },
    { id: "NR-6", kind: "positive", cls: "stored XSS via dangerouslySetInnerHTML", locations: ["src/pages/Dashboard.tsx"], match: ["xss", "dangerouslysetinnerhtml"], note: "The one finding the original static-only measurement caught." },
    { id: "NR-7", kind: "positive", cls: "prompt injection into the LLM call, no input validation", locations: ["src/lib/ai.ts"], match: ["prompt injection", "prompt-injection"], note: "No mechanical detector models this class — semantic-only by design." },
    { id: "NR-8", kind: "positive", cls: "no rate limit on the AI call + billing secret in a public-readable table", locations: ["src/lib/ai.ts", "schema.sql"], match: ["rate limit", "rate-limit", "stripe_customer_id", "billing"], note: "M10 corroborates the billing half; the rate-limit half is browser-direct with no server to gate." },
  ],
};

const superRedHat: SemanticTarget = {
  slug: "superredhat",
  repo: "SuperRedHat/secure-code-review-demo",
  ref: "vulnerable",
  source: "docs/design/superredhat-recall-measurement.md",
  recordedOn: "2026-07-24",
  recordedCaught: 12,
  entries: [
    { id: "F-01", kind: "positive", cls: "hardcoded Supabase service-role key", locations: ["lib/supabaseAdmin.ts"], match: ["service_role", "service-role", "credential"], note: "" },
    { id: "F-02", kind: "positive", cls: "RLS disabled on every table", locations: ["supabase/migrations"], match: ["rls", "row level security", "row-level security"], note: "" },
    { id: "F-03", kind: "positive", cls: "IDOR — notes read/written by id with no ownership check", locations: ["app/api/notes/[id]/route.ts"], match: ["idor", "object-level", "ownership", "owner"], note: "The report flags this as scanner-invisible; semantic + M2 are the tiers that reach it." },
    { id: "F-04", kind: "positive", cls: "admin authorization enforced in the UI only", locations: ["app/api/admin/users/route.ts", "app/admin/page.tsx"], match: ["role check", "function-level", "bfla", "authorization"], note: "Right-file/wrong-mechanism mechanically for a long time (#561) — keywords name the mechanism so a filename heuristic can't score." },
    { id: "F-05", kind: "positive", cls: "SSRF in the avatar proxy / URL import", locations: ["lib/fetchUrl.ts", "app/api/avatar/route.ts", "app/api/import/route.ts"], match: ["ssrf"], note: "" },
    { id: "F-06", kind: "positive", cls: "stored XSS via dangerouslySetInnerHTML", locations: ["app/notes/[id]/page.tsx"], match: ["xss", "dangerouslysetinnerhtml"], note: "" },
    { id: "F-07", kind: "positive", cls: "mass assignment / over-posting on note writes", locations: ["app/api/notes/route.ts", "app/api/notes/[id]/route.ts"], match: ["mass assignment", "mass-assignment", "over-post", "overposting", "whitelist"], note: "" },
    { id: "F-08", kind: "positive", cls: "Math.random token + MD5 hashing for API tokens", locations: ["lib/tokens.ts"], match: ["math.random", "md5", "weak hash", "randomness"], note: "" },
    { id: "F-09", kind: "positive", cls: "insecure JWT — no expiry, unpinned alg, hardcoded fallback secret", locations: ["lib/jwt.ts"], match: ["jwt", "expiresin", "algorithm", "secret"], note: "Mechanical caught 1 of 3 facets; the semantic tier carried the other two (mechanized since, #595)." },
    { id: "F-10", kind: "positive", cls: "wildcard CORS on the authenticated API", locations: ["lib/cors.ts"], match: ["cors"], note: "" },
    { id: "F-11", kind: "positive", cls: "no CSRF protection / no rate limiting", locations: ["app/api/notes", "app/api/import/route.ts"], match: ["csrf", "rate limit", "rate-limit"], note: "No static detector exists at all — semantic and the M2 CSRF probe are the only tiers that reach it." },
    { id: "F-12", kind: "positive", cls: "vulnerable ejs dependency + SSTI render endpoint", locations: ["package.json", "app/api/render/route.ts"], match: ["ejs", "ssti", "template injection"], note: "" },
    {
      id: "F-N1",
      kind: "negative",
      cls: "the notes / import routes reported as UNAUTHENTICATED — false: both call getUser() and 401 first",
      locations: ["app/api/notes/route.ts", "app/api/import/route.ts"],
      match: ["unauthenticated", "no auth-check", "missing auth", "no authentication"],
      note: "NOT a finding. app/api/notes/route.ts (POST) and app/api/import/route.ts both call getUser(req) and return 401 when it is null — they are authenticated. The measurement recorded harvey-route-noauth firing here on a FALSE 'no auth' premise (#562); a semantic pass that repeats it (reports these routes as unauthenticated) is believing a filename/heuristic over the code. The real bugs on these files are F-07 (mass assignment) and F-11 (CSRF/rate-limit), which name their own mechanisms.",
    },
  ],
};

const supatest: SemanticTarget = {
  slug: "supatest",
  repo: "yoanbernabeu/SupatestVibeDemo",
  ref: "main",
  source: "docs/design/supatest-recall-measurement.md",
  recordedOn: "2026-07-24",
  recordedCaught: 9,
  entries: [
    { id: "F1", kind: "positive", cls: "UPDATE articles guarded by an always-true tautology", locations: ["supabase/migrations"], match: ["update", "tautology"], note: "Engineered to pass the Supabase linter; the mechanical CLAUSE_TRUE check only matches literal `true`." },
    { id: "F2", kind: "positive", cls: "DELETE articles guarded by the same tautology", locations: ["supabase/migrations"], match: ["delete", "tautology"], note: "" },
    { id: "F3", kind: "positive", cls: "unpublished drafts readable by anon (SELECT USING(true))", locations: ["supabase/migrations", "src/components/ArticleList.tsx"], match: ["draft", "unpublished", "published"], note: "Mechanically only disclosed as an unassessed tenancy-model indicator." },
    { id: "F4", kind: "positive", cls: "public avatars storage bucket — uploads world-readable", locations: ["src/components/Profile.tsx"], match: ["bucket", "storage", "getpublicurl"], note: "The mechanical public-bucket detector is connected/live tier." },
    { id: "F5", kind: "positive", cls: "user enumeration via an unrestricted SECURITY DEFINER RPC", locations: ["supabase/migrations", "src/components/Auth.tsx"], match: ["security definer", "get_user_by_email", "enumeration"], note: "" },
    { id: "F6", kind: "positive", cls: "unauthenticated Realtime subscription streams every change", locations: ["src/components/ArticleList.tsx"], match: ["realtime", "postgres_changes", "subscribe"], note: "" },
    { id: "F7", kind: "positive", cls: "weak password policy (no HIBP, no complexity)", locations: ["src/components/Auth.tsx"], match: ["password"], note: "Config-to-verify: the setting lives in project Auth config, so the semantic pass flags it for confirmation." },
    { id: "F8", kind: "positive", cls: "open self-service signup with auto-confirm", locations: ["src/components/Auth.tsx"], match: ["signup", "sign-up", "auto-confirm", "autoconfirm"], note: "Config-to-verify, as F7." },
    { id: "F9", kind: "positive", cls: "profiles policies expose every email and allow any edit/delete", locations: ["supabase/migrations"], match: ["profiles"], note: "" },
    {
      id: "F-N1",
      kind: "negative",
      cls: "the Supabase anon/publishable key in the browser client reported as an exposed secret — public by design",
      locations: ["src/lib/supabase.ts"],
      match: ["anon key", "publishable", "exposed secret", "hardcoded supabase key"],
      note: "NOT a finding. src/lib/supabase.ts hands the VITE_SUPABASE_ANON_KEY to createClient in browser code — the anon key is public by design (its access is exactly what RLS allows), and the file even documents this. A semantic pass that reports it as an exposed/committed secret is the fp-rules.txt anon-key false positive; security here rests on RLS, which is where the real flaws (F1-F9) live.",
    },
  ],
};

const cipherx: SemanticTarget = {
  slug: "cipherx",
  repo: "thecipherxpro/cipherx-vulnerability-lab",
  ref: "main",
  source: "docs/design/cipherx-recall-measurement.md",
  recordedOn: "2026-07-24",
  recordedCaught: 20,
  entries: [
    { id: "CX-01", kind: "positive", cls: "weak/default seeded account credentials", locations: ["scripts/seed-auth-users.ts"], match: ["password", "credential"], note: "" },
    { id: "CX-02", kind: "positive", cls: "service-role + anon JWT committed in a tracked .env", locations: [".env"], match: ["service_role", "service-role", "jwt"], note: "" },
    { id: "CX-03", kind: "positive", cls: "secrets backup file with AWS/Stripe/JWT/SMTP keys", locations: ["public/.env.backup"], match: ["aws", "stripe", "secret", "credential"], note: "" },
    { id: "CX-04", kind: "positive", cls: "sensitive files served from the web root", locations: ["public/"], match: ["sensitive file", "backup", ".bak", "served from"], note: "" },
    { id: "CX-05", kind: "positive", cls: "invoices readable by every authenticated user", locations: ["vulnerable_rls.sql"], match: ["invoices"], note: "" },
    { id: "CX-06", kind: "positive", cls: "support_tickets readable by every authenticated user", locations: ["vulnerable_rls.sql"], match: ["support_tickets"], note: "" },
    { id: "CX-07", kind: "positive", cls: "fake_secrets / fake_files readable by anon", locations: ["vulnerable_rls.sql"], match: ["fake_secrets", "fake_files", "anon"], note: "" },
    { id: "CX-08", kind: "positive", cls: "profiles policy exposes weak_password_hint to any authed user", locations: ["portal_rls.sql"], match: ["weak_password_hint", "profiles"], note: "Mechanical miss — `is_active = true` is not the literal `true` the permissive-policy pass matches." },
    { id: "CX-09", kind: "positive", cls: "employee_records (salary, ssn_last4) readable by any authed user", locations: ["portal_rls.sql", "portal_roles.sql"], match: ["employee_records", "ssn"], note: "" },
    { id: "CX-10", kind: "positive", cls: "public read storage buckets", locations: ["storage_buckets.sql", "spec_buckets_and_rpc.sql"], match: ["bucket", "storage"], note: "" },
    { id: "CX-11", kind: "positive", cls: "SECURITY DEFINER RPCs granted to anon that dump/enumerate data", locations: ["vulnerable_rpc.sql", "spec_buckets_and_rpc.sql"], match: ["security definer", "grant execute", "anon"], note: "" },
    { id: "CX-12", kind: "positive", cls: "plpgsql SQL injection via dynamic EXECUTE concatenation", locations: ["spec_buckets_and_rpc.sql"], match: ["sql injection", "sqli", "execute"], note: "" },
    { id: "CX-13", kind: "positive", cls: "IDOR — any invoice returned by id with no company_id check", locations: ["src/app/api/invoices/[id]/route.ts"], match: ["idor", "ownership", "company_id", "object-level"], note: "" },
    { id: "CX-14", kind: "positive", cls: "mass assignment on profile update (no field whitelist)", locations: ["src/app/api/profile/route.ts"], match: ["mass assignment", "over-post", "whitelist"], note: "" },
    { id: "CX-15", kind: "positive", cls: "X-User-Role header trusted, then service-role client dumps secrets", locations: ["src/app/api/internal/users/route.ts"], match: ["x-user-role", "header", "service role", "function-level"], note: "" },
    { id: "CX-16", kind: "positive", cls: "SSRF webhook fetch reaching cloud metadata", locations: ["src/app/api/webhook/route.ts"], match: ["ssrf"], note: "" },
    { id: "CX-17", kind: "positive", cls: "reflected XSS into an HTML response + reflected CORS with credentials", locations: ["src/app/api/tickets/search/route.ts", "src/app/api/debug/route.ts"], match: ["xss", "cors", "reflected"], note: "" },
    { id: "CX-18", kind: "positive", cls: "verbose errors leaking connection string, stack, env, cwd", locations: ["src/app/api/debug/route.ts", "src/app/api/profile/route.ts", "src/app/api/invoices/[id]/route.ts"], match: ["stack", "verbose", "information disclosure", "connection string", "process.cwd"], note: "" },
    { id: "CX-19", kind: "positive", cls: "password-reset token returned in the response + no rate limit", locations: ["src/app/api/password-reset/route.ts"], match: ["token", "reset", "rate limit"], note: "" },
    { id: "CX-20", kind: "positive", cls: "security headers unset + server-wide wildcard CORS", locations: [".htaccess", "next.config"], match: ["csp", "content-security-policy", "x-frame", "cors"], note: "" },
    {
      id: "CX-21",
      kind: "negative",
      cls: "advertised 'outdated dependencies' endpoint returning a hard-coded mock CVE list",
      locations: ["src/app/api/dependencies/route.ts"],
      match: ["dependency", "cve", "outdated", "vulnerable component"],
      note: "NOT a real vulnerability — the endpoint returns static JSON and the real package.json deps are current. The target advertises it as a planted bug, so it is the corpus's one recorded semantic FP TRAP: reporting it means the pass believed the repo's own marketing over its code. fp-rules.txt (mock data is not a dependency finding) is what keeps it out.",
    },
    {
      id: "CX-22",
      kind: "negative",
      cls: "the Supabase anon/publishable key in the browser client reported as a committed secret — public by design",
      locations: ["src/lib/supabase/client.ts"],
      match: ["anon key", "publishable", "exposed secret", "hardcoded credential"],
      note: "NOT a finding. src/lib/supabase/client.ts passes NEXT_PUBLIC_SUPABASE_ANON_KEY (decoded role:anon) to createBrowserClient — public by design. This target ALSO commits a real service_role key in .env (CX-02), so the pass must distinguish the two by the decoded role claim (fp-rules.txt); flagging the anon key as a committed credential is failing exactly that distinction.",
    },
  ],
};

export const SEMANTIC_CORPUS: SemanticTarget[] = [nocodeRescue, superRedHat, supatest, cipherx];

// ---------------------------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------------------------

function haystack(f: Finding): string {
  return `${f.id} ${f.title} ${f.taxonomy} ${f.evidence} ${f.location}`.toLowerCase();
}

function matches(entry: SemanticEntry, f: Finding): boolean {
  const loc = f.location.toLowerCase();
  if (!entry.locations.some((l) => loc.includes(l.toLowerCase()))) return false;
  const hay = haystack(f);
  return entry.match.some((k) => hay.includes(k.toLowerCase()));
}

export interface SemanticRow {
  id: string;
  kind: SemanticEntry["kind"];
  cls: string;
  matched: number; // findings in the pass that satisfied this entry
  pass: boolean;
  detail: string;
}

export interface SemanticTargetResult {
  slug: string;
  repo: string;
  scored: boolean;
  // Set ONLY when scored === false: why this target could not be scored. Never omitted, never
  // replaced by a zero — an unscored target must be legible as unscored in the tally.
  reason?: string;
  rows: SemanticRow[];
  positivesTotal: number;
  positivesCaught: number;
  negativesTotal: number;
  negativesCleared: number;
  recall: number;
  recordedCaught: number;
  recordedOn: string;
  source: string;
  regressed: boolean; // caught fewer positives than the recorded baseline
  generatedAt?: string; // the scored artifact's timestamp
  // Findings that satisfied more than one entry. Location+keyword matching is generous, so this is
  // the number that says how much of the recall rests on one finding covering two planted bugs.
  sharedFindings: number;
}

type PassLoad = { ok: true; artifact: PassArtifact } | { ok: false; reason: string };

// Validates one target's semantic pass artifact. Rejections carry the reason the CLI prints — the
// #416 rule ("a rejected artifact fails loud, it is never silently ignored") applied to scoring.
export function loadSemanticPass(raw: unknown, target: SemanticTarget, path: string, now: number): PassLoad {
  if (raw === undefined) {
    return {
      ok: false,
      reason: `no artifact at ${path} — the semantic pass has not been recorded for this target. Run the pass over a clone of ${target.repo}@${target.ref}${target.scope ? `/${target.scope}` : ""}, then: pnpm record-pass --module M1 --pass semantic --target <clone> --findings <triage.json> --out <artifacts-dir>/${target.slug}`,
    };
  }
  const a = raw as Partial<PassArtifact>;
  if (a.module !== "M1") return { ok: false, reason: `${path} records module ${a.module ?? "<none>"}, not M1 — this gate scores the M1 semantic pass` };
  if (a.pass !== "semantic") return { ok: false, reason: `${path} records the "${a.pass ?? "<none>"}" pass, not "semantic" — a mechanical/dynamic/verdict artifact cannot score the semantic tier` };
  const ts = a.generatedAt ? Date.parse(a.generatedAt) : NaN;
  if (Number.isNaN(ts)) return { ok: false, reason: `${path} has no valid generatedAt timestamp — cannot judge whether this pass describes the current briefs` };
  if (now - ts > MAX_PASS_AGE_MS) {
    const ageDays = Math.round((now - ts) / (24 * 60 * 60 * 1000));
    return { ok: false, reason: `${path} is stale (generated ${a.generatedAt}, ${ageDays} days ago, past the ${Math.round(MAX_PASS_AGE_MS / (24 * 60 * 60 * 1000))}-day window) — re-run the semantic pass` };
  }
  if (!a.findings) {
    return { ok: false, reason: `${path} carries no findings array — record-pass drops an empty one, so this cannot be told apart from "the pass ran and reported nothing". Re-record with --findings <triage.json>` };
  }
  return { ok: true, artifact: a as PassArtifact };
}

// Scores one target's pass findings against its answer key.
export function scoreSemanticPass(target: SemanticTarget, findings: Finding[], generatedAt?: string): SemanticTargetResult {
  const hits = new Map<Finding, number>();
  const rows: SemanticRow[] = target.entries.map((entry) => {
    const relevant = findings.filter((f) => matches(entry, f));
    for (const f of relevant) hits.set(f, (hits.get(f) ?? 0) + 1);
    const matched = relevant.length;
    const pass = entry.kind === "positive" ? matched > 0 : matched === 0;
    const detail =
      entry.kind === "positive"
        ? pass
          ? `caught (${matched} finding${matched === 1 ? "" : "s"})`
          : "NOT caught by the semantic pass"
        : pass
          ? "cleared — not reported"
          : `FALSE POSITIVE — the pass reported ${matched} finding(s) on a non-vulnerability`;
    return { id: entry.id, kind: entry.kind, cls: entry.cls, matched, pass, detail };
  });

  const pos = rows.filter((r) => r.kind === "positive");
  const neg = rows.filter((r) => r.kind === "negative");
  const positivesCaught = pos.filter((r) => r.pass).length;
  return {
    slug: target.slug,
    repo: target.repo,
    scored: true,
    rows,
    positivesTotal: pos.length,
    positivesCaught,
    negativesTotal: neg.length,
    negativesCleared: neg.filter((r) => r.pass).length,
    recall: pos.length === 0 ? 0 : positivesCaught / pos.length,
    recordedCaught: target.recordedCaught,
    recordedOn: target.recordedOn,
    source: target.source,
    regressed: positivesCaught < target.recordedCaught,
    generatedAt,
    sharedFindings: [...hits.values()].filter((n) => n > 1).length,
  };
}

// The not-scored result: every corpus target produces a row whether or not its pass ran, so a
// missing pass appears in the tally instead of shrinking the denominator.
export function unscoredTarget(target: SemanticTarget, reason: string): SemanticTargetResult {
  const pos = target.entries.filter((e) => e.kind === "positive").length;
  return {
    slug: target.slug,
    repo: target.repo,
    scored: false,
    reason,
    rows: [],
    positivesTotal: pos,
    positivesCaught: 0,
    negativesTotal: target.entries.length - pos,
    negativesCleared: 0,
    recall: 0,
    recordedCaught: target.recordedCaught,
    recordedOn: target.recordedOn,
    source: target.source,
    regressed: false, // an unrun pass is not a regression — it is an absence, reported as one
    sharedFindings: 0,
  };
}

interface SemanticMatrix {
  targets: SemanticTargetResult[];
  scoredTargets: number;
  unscoredTargets: number;
  positivesTotal: number; // over SCORED targets only — the denominator of a number we measured
  positivesCaught: number;
  negativesTotal: number;
  negativesCleared: number;
  ok: boolean;
}

// The gate verdict. FAIL on: a regression below a recorded baseline, a false positive on a recorded
// non-vulnerability, or NOTHING SCORED — because "no target could be scored" must never exit 0 and
// read as a clean gate.
export function summarizeSemantic(targets: SemanticTargetResult[]): SemanticMatrix {
  const scored = targets.filter((t) => t.scored);
  const sum = (pick: (t: SemanticTargetResult) => number) => scored.reduce((n, t) => n + pick(t), 0);
  const negativesTotal = sum((t) => t.negativesTotal);
  const negativesCleared = sum((t) => t.negativesCleared);
  return {
    targets,
    scoredTargets: scored.length,
    unscoredTargets: targets.length - scored.length,
    positivesTotal: sum((t) => t.positivesTotal),
    positivesCaught: sum((t) => t.positivesCaught),
    negativesTotal,
    negativesCleared,
    ok: scored.length > 0 && !scored.some((t) => t.regressed) && negativesCleared === negativesTotal,
  };
}
