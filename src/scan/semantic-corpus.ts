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
//   - Matching is location + mechanism phrase, the same shape calibration.ts uses. The phrases are
//     deliberately discriminating: sharing a file with another vulnerability is never enough to
//     score. scoreSemanticPass still reports findings shared by multiple entries when one piece of
//     evidence proves two distinct impacts.

import type { Finding } from "../findings.js";
import { MAX_PASS_AGE_MS, type PassArtifact } from "../audit-pass-artifact.js";

export interface SemanticEntry {
  id: string;
  kind: "positive" | "negative";
  cls: string;
  // Any-of: the finding's location must contain one of these (case-insensitive substring), which is
  // what pins a finding to the planted bug's file rather than to its wording alone.
  locations: string[];
  // Any-of: at least one must appear in the finding's id/title/taxonomy/evidence. These
  // name the MECHANISM, so a right-file/wrong-mechanism finding (the "partial" the measurement docs
  // record) does not score as a catch.
  match: string[];
  // Any-of groups, each of which is all-of. This carries stable mechanism concepts without making
  // their prose order part of the answer key.
  matchAll?: string[][];
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
  // `master`, not `main` — corrected 2026-07-30 (#1185). MEASURED: `git clone --branch main
  // https://github.com/yagaMI-Reverse/nocode-rescue.git` exits 128 ("Remote branch main not found
  // in upstream origin") and origin/HEAD resolves to origin/master. `ref` is not decorative here:
  // loadSemanticPass prints it as the clone command an operator is told to run, so the wrong value
  // sent every reader at a command that exits 128.
  ref: "master",
  scope: "before",
  source: "docs/design/nocode-rescue-recall-measurement.md",
  recordedOn: "2026-09-04",
  recordedCaught: 5,
  entries: [
    { id: "NR-2", kind: "positive", cls: "OpenAI key shipped to the browser + dangerouslyAllowBrowser", locations: ["src/lib/ai.ts"], match: ["dangerouslyallowbrowser"], matchAll: [["openai", "browser", "key"], ["openai", "browser", "credential"], ["vite_openai_api_key", "browser"]], note: "Audited at the pinned source and confirmed 3/0/0 in the 2026-09-03 triage." },
    { id: "NR-3", kind: "positive", cls: "RLS off on tickets/profiles/workspaces", locations: ["schema.sql"], match: ["rls", "row level security", "row-level security"], note: "Mechanically blocked by the unqualified `create table` regex (residual gap B); semantic + dynamic carry it." },
    { id: "NR-4", kind: "positive", cls: "authentication enforced only in the client", locations: ["src/pages/Dashboard.tsx"], match: ["authentication is enforced only", "client-only authentication", "client-side authentication"], matchAll: [["localstorage", "identity"], ["localstorage", "authentication"], ["client-controlled", "identity"]], note: "Narrowed so the adjacent role/workspace authorization finding cannot score this row." },
    { id: "NR-5", kind: "positive", cls: "client-controlled role and workspace authorize cross-tenant operations", locations: ["src/pages/Dashboard.tsx"], match: ["role and workspace authorize cross-tenant"], matchAll: [["localstorage", "workspace", "admin"], ["client-controlled", "role", "workspace"]], note: "Narrowed so the adjacent localStorage authentication finding cannot score this row." },
    { id: "NR-6", kind: "positive", cls: "stored XSS via dangerouslySetInnerHTML", locations: ["src/pages/Dashboard.tsx"], match: ["xss", "dangerouslysetinnerhtml"], note: "The one finding the original static-only measurement caught." },
  ],
};

const superRedHat: SemanticTarget = {
  slug: "superredhat",
  repo: "SuperRedHat/secure-code-review-demo",
  ref: "vulnerable",
  source: "docs/design/superredhat-recall-measurement.md",
  recordedOn: "2026-09-04",
  recordedCaught: 9,
  entries: [
    { id: "F-01", kind: "positive", cls: "hardcoded Supabase service-role key", locations: ["lib/supabaseAdmin.ts"], match: ["service_role", "service-role"], matchAll: [["supabase", "service role"], ["hardcoded", "service role"]], note: "" },
    { id: "F-02", kind: "positive", cls: "RLS disabled on every table", locations: ["supabase/migrations"], match: ["rls", "row level security", "row-level security"], note: "" },
    { id: "F-03", kind: "positive", cls: "IDOR — notes read/written by id with no ownership check", locations: ["app/api/notes/[id]/route.ts"], match: ["idor", "object-level"], matchAll: [["note", "ownership", "check"], ["note", "owner", "check"]], note: "The report flags this as scanner-invisible; semantic + M2 are the tiers that reach it." },
    { id: "F-04", kind: "positive", cls: "admin authorization enforced in the UI only", locations: ["app/api/admin/users/route.ts", "app/admin/page.tsx"], match: ["role check", "function-level", "bfla"], matchAll: [["admin", "role"], ["admin", "server-side"]], note: "Right-file/wrong-mechanism mechanically for a long time (#561) — keywords name the mechanism so a filename heuristic can't score." },
    { id: "F-05", kind: "positive", cls: "SSRF in the avatar proxy / URL import", locations: ["lib/fetchUrl.ts", "app/api/avatar/route.ts", "app/api/import/route.ts"], match: ["ssrf"], note: "" },
    { id: "F-06", kind: "positive", cls: "stored XSS via dangerouslySetInnerHTML", locations: ["app/notes/[id]/page.tsx"], match: ["xss", "dangerouslysetinnerhtml"], note: "" },
    { id: "F-07", kind: "positive", cls: "mass assignment / over-posting on note writes", locations: ["app/api/notes/route.ts", "app/api/notes/[id]/route.ts"], match: ["mass assignment", "mass-assignment", "over-post", "overposting", "whitelist"], note: "" },
    { id: "F-09", kind: "positive", cls: "public fallback JWT secret permits forged application sessions", locations: ["lib/jwt.ts"], match: ["fallback secret", "public fallback", "source-visible signing key"], matchAll: [["jwt", "fallback", "secret"], ["session", "signing", "key"]], note: "Narrowed to the proven fallback-secret forgery path; generic `secret` in this file no longer scores." },
    { id: "F-12", kind: "positive", cls: "vulnerable ejs dependency + SSTI render endpoint", locations: ["package.json", "app/api/render/route.ts"], match: ["ejs", "ssti", "template injection"], note: "" },
    {
      id: "F-N1",
      kind: "negative",
      cls: "the notes / import routes reported as UNAUTHENTICATED — false: both call getUser() and 401 first",
      locations: ["app/api/notes/route.ts", "app/api/import/route.ts"],
      match: ["unauthenticated", "no auth-check", "missing auth", "no authentication"],
      note: "NOT a finding. app/api/notes/route.ts (POST) and app/api/import/route.ts both call getUser(req) and return 401 when it is null — they are authenticated. The measurement recorded harvey-route-noauth firing here on a FALSE 'no auth' premise (#562); a semantic pass that repeats it is believing a filename/heuristic over the code. The real bugs on these paths are independently named by F-05 and F-07.",
    },
  ],
};

const supatest: SemanticTarget = {
  slug: "supatest",
  repo: "yoanbernabeu/SupatestVibeDemo",
  ref: "main",
  source: "docs/design/supatest-recall-measurement.md",
  recordedOn: "2026-09-04",
  recordedCaught: 5,
  entries: [
    { id: "F1", kind: "positive", cls: "UPDATE articles guarded by an always-true tautology", locations: ["supabase/migrations"], match: ["article update policy"], matchAll: [["article", "update", "policy"]], note: "The exact mechanism phrase prevents adjacent profile-policy findings from scoring this row." },
    { id: "F2", kind: "positive", cls: "DELETE articles guarded by the same tautology", locations: ["supabase/migrations"], match: ["article delete policy"], matchAll: [["article", "delete", "policy"]], note: "The completed-triage adapter carries the validated f006 duplicate provenance onto canonical f005." },
    { id: "F3", kind: "positive", cls: "unpublished drafts readable by anon (SELECT USING(true))", locations: ["supabase/migrations"], match: ["exposes unpublished drafts", "unpublished draft"], note: "Narrowed to the source-proven SELECT exposure." },
    { id: "F5", kind: "positive", cls: "profile PII exposed by an unrestricted SECURITY DEFINER RPC", locations: ["supabase/migrations"], match: ["security definer rpc exposes profile pii", "without caller authorization"], matchAll: [["security definer", "profile", "pii"], ["security definer", "profile", "email"], ["rpc", "profile", "email"]], note: "Narrowed to the source-proven RPC and PII mechanism." },
    { id: "F9", kind: "positive", cls: "profile email exposure plus unrestricted profile edit/delete policies", locations: ["supabase/migrations"], match: ["profile policy exposes every user's email", "profile update policy", "profile delete policy"], matchAll: [["profile", "email", "policy"], ["profile", "update", "policy"], ["profile", "delete", "policy"]], note: "One audited policy-family row; generic mentions of profiles do not score it." },
    {
      id: "F-N1",
      kind: "negative",
      cls: "the Supabase anon/publishable key in the browser client reported as an exposed secret — public by design",
      locations: ["src/lib/supabase.ts"],
      match: ["anon key", "publishable", "exposed secret", "hardcoded supabase key"],
      note: "NOT a finding. src/lib/supabase.ts hands the VITE_SUPABASE_ANON_KEY to createClient in browser code — the anon key is public by design (its access is exactly what RLS allows), and the file even documents this. A semantic pass that reports it as an exposed/committed secret is the fp-rules.txt anon-key false positive; security here rests on the source-proven policy flaws F1/F2/F3/F5/F9.",
    },
  ],
};

const cipherx: SemanticTarget = {
  slug: "cipherx",
  repo: "thecipherxpro/cipherx-vulnerability-lab",
  ref: "main",
  source: "docs/design/cipherx-recall-measurement.md",
  recordedOn: "2026-09-04",
  recordedCaught: 16,
  entries: [
    { id: "CX-01", kind: "positive", cls: "weak/default seeded account credentials disclosed from public static paths", locations: [".htaccess", "public/"], match: ["account credentials", "account/password pairs", "privileged account"], matchAll: [["seeded", "account", "password"], ["public", "username", "password"], ["served", "admin", "password"]], note: "The public-disclosure finding ties the published pairs to active source-provisioned accounts; the last clause accepts the same proof when a fresh reviewer leads with the served backup rather than the seed." },
    { id: "CX-02", kind: "positive", cls: "service-role + anon JWT committed in a tracked .env", locations: [".env"], match: ["service_role", "service-role"], matchAll: [["committed", "service role"], ["hardcoded", "service role"]], note: "" },
    { id: "CX-04", kind: "positive", cls: "sensitive files served from the web root", locations: [".htaccess", "public/"], match: ["public static paths", "backup configuration", "robots advertises"], matchAll: [["public", "backup", "configuration"], ["web root", "sensitive", "file"], ["robots", "backup"]], note: "Narrowed to the proven deployed static-path exposure; decoy secret text alone does not score." },
    { id: "CX-10", kind: "positive", cls: "public and cross-user storage bucket reads", locations: ["storage_buckets.sql", "spec_buckets_and_rpc.sql"], match: ["storage policies publish backups", "public-backup", "bucket-wide reads"], matchAll: [["storage", "bucket", "public"], ["storage", "backup", "read"]], note: "Narrowed to the audited storage-policy finding." },
    { id: "CX-12", kind: "positive", cls: "plpgsql SQL injection via dynamic EXECUTE concatenation", locations: ["spec_buckets_and_rpc.sql"], match: ["concatenates caller input into dynamic sql", "sql-injection", "dynamic sql executed"], matchAll: [["sql injection", "dynamic sql"], ["execute", "caller input"]], note: "" },
    { id: "CX-15", kind: "positive", cls: "X-User-Role header trusted, then service-role client dumps secrets", locations: ["src/app/api/internal/users/route.ts"], match: ["x-user-role", "function-level"], matchAll: [["role", "header", "service role"], ["role", "header", "service-role"], ["role", "query", "service role"], ["role", "query", "service-role"], ["x-user-role", "secret"]], note: "" },
    { id: "CX-16", kind: "positive", cls: "SSRF webhook fetch reaching cloud metadata", locations: ["src/app/api/webhook/route.ts"], match: ["ssrf"], note: "" },
    { id: "CX-17", kind: "positive", cls: "reflected and stored XSS in the ticket HTML response", locations: ["src/app/api/tickets/search/route.ts"], match: ["xss", "executable html", "raw html"], note: "The unverified credentialed-CORS facet was removed from this row." },
    { id: "CX-18", kind: "positive", cls: "public debug route discloses credentials and server internals", locations: ["src/app/api/debug/route.ts"], match: ["public debug route", "live stack", "server internals"], matchAll: [["debug", "stack", "environment"], ["debug", "credential", "public"]], note: "Narrowed to the directly reachable debug response; unrelated error paths cannot score it." },
    { id: "CX-23", kind: "positive", cls: "anon SECURITY DEFINER get_user_by_email enumerates identities and roles", locations: ["vulnerable_rpc.sql"], match: ["get_user_by_email"], note: "Split from retired compound CX-11; canonical triage finding f011." },
    { id: "CX-24", kind: "positive", cls: "anon SECURITY DEFINER search_lab_data returns secrets and cross-tenant rows", locations: ["vulnerable_rpc.sql", "src/app/api/search/route.ts"], match: ["search_lab_data"], note: "Split from retired compound CX-11; accept either the defining migration or the shipped unauthenticated caller when the exact RPC symbol is present." },
    { id: "CX-25", kind: "positive", cls: "anon SECURITY DEFINER export_demo_secrets dumps the secrets table", locations: ["vulnerable_rpc.sql"], match: ["export_demo_secrets"], note: "Split from retired compound CX-11; canonical triage finding f013." },
    { id: "CX-26", kind: "positive", cls: "get_invoice_details SECURITY DEFINER RPC omits caller company scope", locations: ["vulnerable_rpc.sql", "src/app/api/invoices/[id]/route.ts"], match: ["get_invoice_details", "invoice rpc procedures"], note: "Source-proven replacement for retired app-route CX-13. The caller location is accepted only when validated duplicate provenance names the distinct invoice RPC mechanism." },
    { id: "CX-27", kind: "positive", cls: "get_invoice_debug SECURITY DEFINER RPC discloses any invoice by UUID", locations: ["spec_buckets_and_rpc.sql"], match: ["get_invoice_debug", "debug invoice rpc"], note: "Source-proven replacement for retired app-route CX-13; accept the exact symbol or an equivalently specific procedure title." },
    { id: "CX-28", kind: "positive", cls: "signup trigger trusts caller-controlled role metadata", locations: ["initial_schema.sql", "fix_auth_trigger.sql"], match: ["raw_user_meta_data.role", "caller-controlled role metadata"], matchAll: [["signup", "role", "metadata"]], note: "Accept the original trigger declaration or its final replacement definition only when the evidence also names the caller-controlled role mechanism." },
    { id: "CX-29", kind: "positive", cls: "authenticated SECURITY DEFINER debug_fake_secret_dump returns every secret", locations: ["spec_buckets_and_rpc.sql"], match: ["debug_fake_secret_dump"], note: "Added from the 3/0/0 audited triage finding f017." },
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

export function matchesSemanticEntry(entry: SemanticEntry, f: Finding): boolean {
  const loc = f.location.toLowerCase();
  if (!entry.locations.some((l) => loc.includes(l.toLowerCase()))) return false;
  // Location is deliberately absent. It is the independently checked anchor, not proof of a
  // mechanism, and letting it into this text recreated the right-file/wrong-mechanism defect.
  const hay = `${f.id} ${f.title} ${f.taxonomy} ${f.evidence}`.toLowerCase();
  return entry.match.some((key) => hay.includes(key.toLowerCase())) ||
    (entry.matchAll ?? []).some((group) => group.length > 0 && group.every((key) => hay.includes(key.toLowerCase())));
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
  // #1522: the M1 slot accumulates its tiers, so score the semantic pass wherever it sits. Reading
  // only the newest one meant a connected or live pass recorded afterwards left this gate reporting
  // the target unscored — the recall number quietly dropping because an operator recorded MORE.
  const held = [a, ...(a.priorPasses ?? [])];
  const semantic = held.find((p) => p.pass === "semantic");
  if (!semantic) {
    return { ok: false, reason: `${path} holds the ${held.map((p) => `"${p.pass ?? "<none>"}"`).join(", ")} pass(es) and no "semantic" one — a mechanical/dynamic/verdict artifact cannot score the semantic tier` };
  }
  const ts = semantic.generatedAt ? Date.parse(semantic.generatedAt) : NaN;
  if (Number.isNaN(ts)) return { ok: false, reason: `${path} has no valid generatedAt timestamp — cannot judge whether this pass describes the current briefs` };
  if (now - ts > MAX_PASS_AGE_MS) {
    const ageDays = Math.round((now - ts) / (24 * 60 * 60 * 1000));
    return { ok: false, reason: `${path} is stale (generated ${semantic.generatedAt}, ${ageDays} days ago, past the ${Math.round(MAX_PASS_AGE_MS / (24 * 60 * 60 * 1000))}-day window) — re-run the semantic pass` };
  }
  if (!semantic.findings) {
    return { ok: false, reason: `${path} carries no findings array — record-pass drops an empty one, so this cannot be told apart from "the pass ran and reported nothing". Re-record with --findings <triage.json>` };
  }
  return { ok: true, artifact: semantic as PassArtifact };
}

// Scores one target's pass findings against its answer key.
export function scoreSemanticPass(target: SemanticTarget, findings: Finding[], generatedAt?: string): SemanticTargetResult {
  const hits = new Map<Finding, number>();
  const rows: SemanticRow[] = target.entries.map((entry) => {
    const relevant = findings.filter((f) => matchesSemanticEntry(entry, f));
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
