// Reproducible builder for `semgrep-1.173.0-corpus.json` (#1156, #1150 row 7). Writes a purpose-built
// corpus to a throwaway temp dir — one source file per `parseSemgrepFindings` test scenario, plus
// an inert `.github/workflows/` file for the CI-routing case (created only in temp, never in the
// repo tree) — then runs the same pinned binary, rule/config surface, and output/scope flags as
// `runSemgrep` and prints the real JSON to stdout after the tracked canonicalizer removes run
// telemetry and normalizes ordering/paths. This deliberately small parser corpus does not recreate
// the production Carbon family partition, whose separate 22-part revalidation is recorded at its
// production seam.
// Finding fields and diagnostics are never hand-edited or dropped. Re-capture:
// node src/scan/__fixtures__/semgrep/build-corpus.mjs > /tmp/semgrep-1.173.0-corpus.json
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";

// This file stays directly runnable by `node`, while the one production canonicalizer lives in
// TypeScript beside the fixture contract and is also consumed by fixture-drift.ts.
await import("tsx/esm");
const { canonicalizeSemgrepFixtureOutput, SEMGREP_PINNED_VERSION } = await import("../../fixture-drift-contracts.ts");

// Each entry: relative path in the corpus → source that makes a real semgrep rule fire. The trigger
// snippets mirror the calibration fixtures that already exercise these rules (targets/calibration).
const FILES = {
  // harvey-service-role-in-client — ERROR + HIGH + harveySeverity Critical, carries cwe/owasp.
  "app/AdminPanel.jsx":
    '"use client";\nimport { createClient } from "@supabase/supabase-js";\nconst admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\nexport default function AdminPanel() { return admin ? null : null; }\n',
  // code-string-concat — a registry `.audit.` rule that is still ERROR + HIGH (the audit-routing case).
  "app/calc.js":
    "export default function handler(req, res) {\n  const result = eval(req.body.expr);\n  res.status(200).json({ result });\n}\n",
  // harvey-open-redirect — WARNING + MEDIUM (the review-tier case).
  "app/redirect.js":
    'export default function handler(req, res) {\n  const next = req.query.next || "";\n  res.redirect(next);\n}\n',
  // cors-misconfiguration — registry rule carrying cwe + owasp as ARRAYS (the #455 threading case).
  "lib/cors.js":
    'export function withCors(req, res) {\n  const origin = req.headers.get("origin");\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Access-Control-Allow-Credentials", "true");\n  return res;\n}\n',
  // harvey-permissive-cors — ERROR, keeps the app category (the #996 non-workflow case).
  "lib/express-cors.js":
    'import cors from "cors";\nimport express from "express";\nconst app = express();\napp.use(cors({ origin: true, credentials: true }));\nexport default app;\n',
  // harvey-permissive-cors-bare — carries metadata.harveyTaxonomy (the #996 taxonomy-override case).
  "lib/bare-cors.ts":
    'export const CORS_HEADERS: Record<string, string> = {\n  "Access-Control-Allow-Origin": "*",\n  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",\n};\n',
  // bypass-tls-verification — registry rule that ships cwe + owasp as BARE STRINGS (the #976 case).
  "lib/http.js":
    'import https from "https";\nexport const insecureAgent = new https.Agent({ rejectUnauthorized: false });\n',
  // harvey-dangerously-set-inner-html-prop — a harvey rule with NO references/source (the #1077
  // generic-placeholder case).
  "components/UserBio.tsx":
    'export function UserBio({ user }: { user: { bio: string } }) {\n  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />;\n}\n',
  // npm-missing-minimum-release-age — registry rule carrying references + source (the #1077
  // compose-fix-from-the-rule case).
  ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
  // run-shell-injection — a GitHub Actions workflow whose path routes to CI_PIPELINE_CATEGORY.
  ".github/workflows/release.yml":
    'name: release\non: [issues]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n',
};

const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-corpus-"));
for (const [rel, content] of Object.entries(FILES)) {
  const full = join(dir, rel);
  mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
  writeFileSync(full, content);
}

// A semgrep rule's check_id namespace prefix is derived from the --config PATH. Running from the
// temp root with the rules copied to their real repo-relative location makes harvey-* check_ids come
// out identical to a production run from the repo root (`src.scan.rules.semgrep.harvey-*`) rather
// than carrying the capturing machine's absolute path.
const REPO_RULES = fileURLToPath(new URL("../../rules/semgrep/", import.meta.url));
cpSync(REPO_RULES, join(dir, "src/scan/rules/semgrep"), { recursive: true });

// The rule/config and output/scope argv shared with runSemgrep() (src/scan/semgrep.ts), with the
// individual corpus roots named so emitted paths stay relative and stable across machines.
const args = [
  "--config", "p/typescript",
  "--config", "p/react",
  "--config", "p/nextjs",
  "--config", "p/owasp-top-ten",
  "--config", "p/secrets",
  "--config", "p/security-audit",
  "--config", "src/scan/rules/semgrep/",
  "--exclude", "node_modules",
  "--disable-nosem",
  "--timeout", "0",
  "--time",
  "--json",
  "--verbose",
  // The corpus roots only — not the copied rules tree, so semgrep does not scan its own YAML.
  "app", "lib", "components", ".npmrc", ".github",
];
try {
  const out = execFileSync("semgrep", ["--x-ignore-semgrepignore-files", ...args], {
    cwd: dir,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 128,
  });
  const parsed = JSON.parse(out);
  if (process.env.HARVEY_SEMGREP_RAW_OUTPUT) {
    writeFileSync(process.env.HARVEY_SEMGREP_RAW_OUTPUT, `${JSON.stringify(parsed, null, 2)}\n`);
  }
  if (parsed.version !== SEMGREP_PINNED_VERSION) {
    throw new Error(`Semgrep corpus builder expected ${SEMGREP_PINNED_VERSION}, received ${JSON.stringify(parsed.version)}`);
  }
  const canonical = canonicalizeSemgrepFixtureOutput(parsed, dir);
  process.stdout.write(`${JSON.stringify(canonical, null, 2)}\n`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
