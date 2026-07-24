import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// #493: the OWASP Top-10-2021 category each CWE is officially placed under, per OWASP's own
// published per-category "List of Mapped CWEs" (owasp.org/Top10/2021/A0X_.../index.html,
// fetched and cross-checked 2026-07-17 — the #455 assignments were applied from general
// knowledge and NOT checked against this source at the time). This table is the independent
// authority the harvey-* rules' metadata.owasp is checked against below — it is hand-authored
// from the OWASP source, not derived from the yaml under test, so a wrong yaml value fails here.
const OFFICIAL_CWE_TO_OWASP_2021: Record<string, string> = {
  // A01 — Broken Access Control
  "CWE-22": "A01:2021 - Broken Access Control",
  "CWE-200": "A01:2021 - Broken Access Control",
  "CWE-285": "A01:2021 - Broken Access Control",
  "CWE-352": "A01:2021 - Broken Access Control",
  "CWE-540": "A01:2021 - Broken Access Control",
  "CWE-601": "A01:2021 - Broken Access Control",
  "CWE-639": "A01:2021 - Broken Access Control",
  "CWE-668": "A01:2021 - Broken Access Control",
  "CWE-862": "A01:2021 - Broken Access Control",
  "CWE-863": "A01:2021 - Broken Access Control",
  // A02 — Cryptographic Failures
  "CWE-319": "A02:2021 - Cryptographic Failures",
  "CWE-321": "A02:2021 - Cryptographic Failures",
  "CWE-327": "A02:2021 - Cryptographic Failures",
  "CWE-329": "A02:2021 - Cryptographic Failures",
  "CWE-330": "A02:2021 - Cryptographic Failures",
  "CWE-338": "A02:2021 - Cryptographic Failures",
  "CWE-347": "A02:2021 - Cryptographic Failures",
  // A03 — Injection
  "CWE-78": "A03:2021 - Injection",
  "CWE-88": "A03:2021 - Injection",
  "CWE-79": "A03:2021 - Injection",
  "CWE-89": "A03:2021 - Injection",
  "CWE-94": "A03:2021 - Injection",
  "CWE-113": "A03:2021 - Injection",
  "CWE-116": "A03:2021 - Injection",
  "CWE-470": "A03:2021 - Injection",
  "CWE-943": "A03:2021 - Injection",
  // A04 — Insecure Design
  "CWE-209": "A04:2021 - Insecure Design",
  "CWE-256": "A04:2021 - Insecure Design",
  "CWE-522": "A04:2021 - Insecure Design",
  "CWE-598": "A04:2021 - Insecure Design",
  "CWE-602": "A04:2021 - Insecure Design",
  "CWE-1021": "A04:2021 - Insecure Design",
  // A05 — Security Misconfiguration
  "CWE-611": "A05:2021 - Security Misconfiguration",
  "CWE-614": "A05:2021 - Security Misconfiguration",
  "CWE-942": "A05:2021 - Security Misconfiguration",
  // A07 — Identification and Authentication Failures
  "CWE-295": "A07:2021 - Identification and Authentication Failures",
  "CWE-346": "A07:2021 - Identification and Authentication Failures",
  "CWE-613": "A07:2021 - Identification and Authentication Failures",
  "CWE-798": "A07:2021 - Identification and Authentication Failures",
  // A08 — Software and Data Integrity Failures
  "CWE-353": "A08:2021 - Software and Data Integrity Failures",
  "CWE-502": "A08:2021 - Software and Data Integrity Failures",
  "CWE-829": "A08:2021 - Software and Data Integrity Failures",
  "CWE-915": "A08:2021 - Software and Data Integrity Failures",
  // A09 — Security Logging and Monitoring Failures
  "CWE-117": "A09:2021 - Security Logging and Monitoring Failures",
  // A10 — Server-Side Request Forgery
  "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
};

// #975: CWEs Harvey rules carry that OWASP's official Top-10-2021 mapping does NOT place under any
// category. These rules carry `cwe` but deliberately omit `owasp` — an absent owasp field on these
// is correct, not an oversight, so the test asserts it is absent rather than forcing a wrong bucket.
const NO_OWASP_CWES: Record<string, string> = {
  "CWE-693": "Protection Mechanism Failure — not in any Top-10-2021 category's mapped-CWE list",
  "CWE-489": "Active Debug Code — not in any Top-10-2021 category's mapped-CWE list",
  "CWE-1321": "Prototype Pollution — post-2021 CWE, not in the Top-10-2021 mapping",
  "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS) — DoS is not a Top-10-2021 category",
};

const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)));

interface RuleMeta {
  id: string;
  file: string;
  cwe?: string[];
  owasp?: string[];
}

// Regex extraction rather than a yaml parser: no yaml library is a project dependency, and the
// `cwe:`/`owasp:` metadata this repo emits is always a single-line JSON-compatible flow array
// (verified by grep across every rule file), so a small line-anchored parse is sufficient and
// avoids adding a dependency for one test.
function parseRuleMetadata(fileName: string): RuleMeta[] {
  const text = readFileSync(join(RULES_DIR, fileName), "utf8");
  const blocks = text.split(/\n(?= {2}- id: )/);
  const rules: RuleMeta[] = [];
  for (const block of blocks) {
    const idMatch = block.match(/^ {2}- id: (\S+)/);
    if (!idMatch) continue;
    const cweMatch = block.match(/^\s+cwe:\s*(\[.*\])\s*$/m);
    const owaspMatch = block.match(/^\s+owasp:\s*(\[.*\])\s*$/m);
    rules.push({
      id: idMatch[1]!,
      file: fileName,
      cwe: cweMatch ? (JSON.parse(cweMatch[1]!) as string[]) : undefined,
      owasp: owaspMatch ? (JSON.parse(owaspMatch[1]!) as string[]) : undefined,
    });
  }
  return rules;
}

describe("#493/#975: harvey-* rule metadata.owasp matches OWASP's official 2021 CWE-to-category mapping", () => {
  const files = readdirSync(RULES_DIR).filter((f) => f.endsWith(".yml"));
  const allRules = files.flatMap(parseRuleMetadata);
  const rulesWithCwe = allRules.filter((r) => r.cwe && r.cwe.length > 0);

  // #975: CWE enrichment is now complete — every harvey-* rule carries a CWE (a CWE-indexed
  // consumer, e.g. GitHub code scanning or a BenchProctor-style benchmark, no longer under-credits
  // a real detection as an unmappable finding). A new rule with no cwe fails here loudly.
  it("every harvey-* rule carries metadata.cwe (no rule left uncategorized)", () => {
    const missing = allRules.filter((r) => !r.cwe || r.cwe.length === 0).map((r) => `${r.id} (${r.file})`);
    expect(missing, `rules missing metadata.cwe: ${missing.join(", ")}`).toEqual([]);
    expect(rulesWithCwe.length).toBe(allRules.length);
  });

  it.each(rulesWithCwe.map((r): [string, RuleMeta] => [r.id, r]))("%s: cwe maps to its official OWASP category (or is a deliberate no-owasp CWE)", (_id, rule) => {
    const cweId = rule.cwe![0]!.match(/^CWE-\d+/)?.[0];
    expect(cweId, `${rule.id} (${rule.file}) has an unparseable cwe entry: ${rule.cwe![0]}`).toBeDefined();

    if (NO_OWASP_CWES[cweId!]) {
      // A CWE OWASP does not categorize: owasp must be ABSENT (forcing a bucket would be a wrong claim).
      expect(rule.owasp, `${rule.id}: ${cweId} has no official OWASP Top-10-2021 category (${NO_OWASP_CWES[cweId!]}); owasp must be omitted`).toBeUndefined();
      return;
    }

    const expectedCategory = OFFICIAL_CWE_TO_OWASP_2021[cweId!];
    expect(expectedCategory, `${rule.id} uses ${cweId}, which is neither in the #493-verified mapping table nor the NO_OWASP_CWES set — add it to one before trusting this rule's metadata`).toBeDefined();

    expect(rule.owasp, `${rule.id}: ${cweId} maps to "${expectedCategory}" per OWASP's official 2021 mapping`).toEqual([expectedCategory]);
  });
});
