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
  "CWE-22": "A01:2021 - Broken Access Control",
  "CWE-601": "A01:2021 - Broken Access Control",
  "CWE-352": "A01:2021 - Broken Access Control",
  "CWE-295": "A07:2021 - Identification and Authentication Failures",
  "CWE-347": "A02:2021 - Cryptographic Failures",
  "CWE-89": "A03:2021 - Injection",
  "CWE-79": "A03:2021 - Injection",
  "CWE-78": "A03:2021 - Injection",
  "CWE-94": "A03:2021 - Injection",
  "CWE-502": "A08:2021 - Software and Data Integrity Failures",
  "CWE-611": "A05:2021 - Security Misconfiguration",
  "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
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

describe("#493: harvey-* rule metadata.owasp matches OWASP's official 2021 CWE-to-category mapping", () => {
  const files = readdirSync(RULES_DIR).filter((f) => f.endsWith(".yml"));
  const rulesWithCwe = files.flatMap(parseRuleMetadata).filter((r) => r.cwe && r.cwe.length > 0);

  it("found the 18 harvey-* rules carrying cwe metadata (guards against silently losing coverage)", () => {
    expect(rulesWithCwe.length).toBe(18);
  });

  it.each(rulesWithCwe.map((r): [string, RuleMeta] => [r.id, r]))("%s: owasp category matches OWASP's official mapping for its cwe", (_id, rule) => {
    const cweId = rule.cwe![0]!.match(/^CWE-\d+/)?.[0];
    expect(cweId, `${rule.id} (${rule.file}) has an unparseable cwe entry: ${rule.cwe![0]}`).toBeDefined();

    const expectedCategory = OFFICIAL_CWE_TO_OWASP_2021[cweId!];
    expect(expectedCategory, `${rule.id} uses ${cweId}, which is not in the #493-verified mapping table above — add it there before trusting this rule's owasp field`).toBeDefined();

    expect(rule.owasp, `${rule.id}: ${cweId} maps to "${expectedCategory}" per OWASP's official 2021 mapping`).toEqual([expectedCategory]);
  });
});
