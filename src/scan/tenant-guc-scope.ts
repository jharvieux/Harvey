// #1195 TENANT-GUC-SCOPE — a tenant GUC set with SET rather than SET LOCAL (or set_config's third
// argument left/set false rather than true). OWASP Multi-Tenant Application Security Cheat Sheet
// section 2 documents the RLS policy side (`current_setting('app.current_tenant')`) but not this:
// our own upstream proposal to add it, OWASP/CheatSheetSeries#2309 item 2. Found as a measured gap
// by that sheet's independent corpus (src/scan/calibration/owasp-multitenant.entries.ts,
// P-OWASP-MT-GUC-SESSION).
//
//   await client.query(`SET app.current_tenant = '${tenantId}'`);
//
// WHY IT MATTERS. `SET` (unlike `SET LOCAL` / `set_config(name, value, true)`) sets the GUC for the
// rest of the SESSION, not just the current transaction. Under transaction-mode pooling (PgBouncer/
// Supabase pooler/pgbouncer-rls) the connection is returned to the pool at the end of the
// transaction with the setting still attached, so the NEXT request to borrow that connection runs
// against the PREVIOUS tenant's identifier — a cross-tenant read in which the RLS policy, the
// schema and the application code all still look correct.
//
// A grep, not a dataflow proof: this cannot see whether the pool is in session mode (where SET is
// harmless) or transaction mode (where it leaks), so it stays review tier. Line-scoped rather than
// whole-file, so a query call and its SET/set_config text must appear on the same line — the
// idiomatic one-liner shape for both the template-literal and parameterized forms.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// A raw-SQL execution call — the JS-side call, not the SQL text.
const QUERY_CALL_HINT = /\.(?:query|execute)\s*\(|\$executeRaw/;

// A tenant/org GUC name, by convention (`app.current_tenant`, `app.tenant_id`, `app.org_id`, …).
const TENANT_GUC_NAME = /[\w.]*(?:tenant|organi[sz]ation|org)[\w.]*/.source;

// `SET <tenant GUC> = …` with no LOCAL — the session-scoped, leaks-across-the-pool form.
const SET_NOT_LOCAL = new RegExp(`\\bSET\\s+(?!LOCAL\\b)${TENANT_GUC_NAME}\\s*=`, "i");

// `set_config('<tenant GUC>', …, false)` — the same defect through the function form. `true` (the
// transaction-scoped, correct form) is deliberately not matched.
const SET_CONFIG_UNSAFE = new RegExp(`set_config\\s*\\(\\s*['"]${TENANT_GUC_NAME}['"]\\s*,[^)]*,\\s*false\\s*\\)`, "i");

function slug(path: string): string {
  return path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function detectFile(path: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!QUERY_CALL_HINT.test(line)) continue;
    const setMatch = SET_NOT_LOCAL.exec(line);
    const configMatch = SET_CONFIG_UNSAFE.exec(line);
    const hit = setMatch ?? configMatch;
    if (!hit) continue;
    findings.push(
      mechanicalFinding({
        id: `TENANT-guc-set-not-local-${slug(path)}-${i + 1}`,
        title: `${path}:${i + 1} — tenant GUC set with ${setMatch ? "SET" : "set_config(…, false)"}, not SET LOCAL`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Tenant GUC set with SET rather than SET LOCAL, leaking across a pooled connection",
        location: `${path}:${i + 1}`,
        evidence: `Heuristic "tenant-guc-scope" matched \`${hit[0]}\` in a query call in ${path}:${i + 1}. No LOCAL / third \`true\` argument was found on the same line.`,
        impact:
          "Under transaction-mode pooling this setting outlives the transaction and stays on the connection when it returns to the pool, so the next request to borrow that connection is evaluated against the PREVIOUS tenant's identifier — a cross-tenant read that leaves the RLS policy, schema and application code all looking correct.",
        fix: "Use `SET LOCAL <guc> = …` or `set_config('<guc>', …, true)` so the setting is scoped to the current transaction and cannot outlive it in the pool.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

export function detectTenantGucScopeFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, f.text));
}

export function scanTenantGucScope(projectDir: string): Finding[] {
  return detectTenantGucScopeFindings(walkSourceFiles(projectDir));
}
