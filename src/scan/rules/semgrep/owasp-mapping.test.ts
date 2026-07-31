import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readNamesSafe } from "../../../fs-walk.js";
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
  "CWE-338": "A02:2021 - Cryptographic Failures",
  "CWE-347": "A02:2021 - Cryptographic Failures",
  // A03 — Injection
  "CWE-78": "A03:2021 - Injection",
  "CWE-88": "A03:2021 - Injection",
  // #1273, VERIFIED 2026-07-31 against OWASP's own published A03:2021 "List of Mapped CWEs":
  // CWE-90 (LDAP Injection) and CWE-643 (XPath Injection) are both in it. CWE-1236 (CSV formula
  // injection) is NOT, in that list or any other A0X one, so harvey-csv-formula-injection carries
  // a cwe with no owasp field — the harvey-redos posture.
  "CWE-90": "A03:2021 - Injection",
  "CWE-643": "A03:2021 - Injection",
  "CWE-79": "A03:2021 - Injection",
  "CWE-89": "A03:2021 - Injection",
  "CWE-94": "A03:2021 - Injection",
  "CWE-95": "A03:2021 - Injection",
  "CWE-113": "A03:2021 - Injection",
  "CWE-917": "A03:2021 - Injection",
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
  // A04 — Insecure Design (#1202, MEASURED 2026-07-27 against MITRE's own CWE-235 page,
  // cwe.mitre.org/data/definitions/235.html): Memberships lists category id 1348, which is
  // OWASP Top Ten 2021 A04:2021 - Insecure Design.
  "CWE-235": "A04:2021 - Insecure Design",
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
  // #1021, MEASURED 2026-07-25 against MITRE's own CWE-252 page (cwe.mitre.org/data/definitions/252.html):
  // its Memberships list carries "OWASP Top Ten 2004 Category A7 — Improper Error Handling" and
  // "OWASP Top Ten 2025 Category A10:2025 — Mishandling of Exceptional Conditions", and NO 2021
  // category (no CWE-1344 child). Falsifier: re-read that page's Memberships section — if a
  // 2021 category appears, move CWE-252 into OFFICIAL_CWE_TO_OWASP_2021 instead.
  "CWE-252": "Unchecked Return Value — MITRE's memberships place it under OWASP 2004 A7 and 2025 A10, not any Top-10-2021 category",
  // #1200, MEASURED 2026-07-27 against MITRE's own CWE-770 page (cwe.mitre.org/data/
  // definitions/770.html): Memberships lists CERT/ISA-62443 cross-sections, no OWASP Top Ten
  // mention at all — not just no 2021 category.
  "CWE-770": "Allocation of Resources Without Limits or Throttling — MITRE's memberships carry no OWASP Top Ten mapping of any year",
  // #1200, MEASURED 2026-07-27 against MITRE's own CWE-524 page (cwe.mitre.org/data/
  // definitions/524.html): Memberships lists two SFP/comprehensive-categorization clusters, no
  // OWASP Top Ten mention at all.
  "CWE-524": "Use of Cache Containing Sensitive Information — MITRE's memberships carry no OWASP Top Ten mapping of any year",
  // #1273, VERIFIED 2026-07-31 against OWASP's own A03:2021 "List of Mapped CWEs" page: the list
  // is CWE-20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100,
  // 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917 — CWE-1236 is absent, and it is a
  // post-2021 CWE (the same reason CWE-1321 is here). Falsifier: re-read that page's list; if
  // CWE-1236 appears, move it into OFFICIAL_CWE_TO_OWASP_2021 instead.
  "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File — post-2021 CWE, absent from A03:2021's mapped-CWE list and from every other 2021 category's",
  // #1294, VERIFIED 2026-07-31. harvey-static-iv moved CWE-329 -> CWE-1204 because CWE-329 is
  // CBC-RESTRICTED and its pattern leaves the mode unconstrained. A02:2021's mapped-CWE list is
  // CWE-259, 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336,
  // 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916 — 1204 is absent, and MITRE's own
  // CWE-1204 page lists no OWASP Top Ten membership of any year. So the correction TRADES an owasp
  // category for a correct CWE, which is the right way round: a wrong bucket is a wrong claim.
  "CWE-1204": "Generation of Weak Initialization Vector (IV) — MITRE's memberships carry no OWASP Top Ten mapping of any year; absent from A02:2021's mapped-CWE list",
  // #1294, VERIFIED 2026-07-31. harvey-fail-open moved CWE-285 -> CWE-636 because its shape is a
  // permissive default on error, not specifically an authorization defect (its own planted fixture
  // is a rate limiter). CWE-636 is in neither A01:2021's mapped-CWE list (CWE-22, 23, 35, 59, 200,
  // 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566,
  // 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275) nor A04:2021's, and MITRE's own CWE-636 page
  // places it under OWASP Top Ten 2004 A7 and 2025 A10 — no 2021 category. Same shape as CWE-252.
  "CWE-636": "Not Failing Securely ('Failing Open') — MITRE's memberships place it under OWASP 2004 A7 and 2025 A10, not any Top-10-2021 category",
};

const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)));

interface RuleMeta {
  id: string;
  file: string;
  cwe?: string[];
  owasp?: string[];
  /** #1521: the rule's id + match machinery — everything but `metadata:` and `message:`. */
  machine: string;
  /** #1521: the rule's client-facing `message:` prose. */
  prose: string;
}

// #1521: the subject text the CWE-binding check below reads. The `metadata:` block is removed
// because that is where `cwe:`/`owasp:` live — leaving it in would let a rule satisfy the check by
// restating its own label, the self-matching shape #1355 found in the calibration corpus. Bare
// `CWE-\d+` tokens are stripped from the remainder for the same reason (harvey-argument-injection's
// message names "(CWE-88)" in prose). Comments are excluded too: the split below attaches a rule's
// leading comment block to the PREVIOUS rule, so comment text is not reliably the rule's own.
function splitRuleBody(block: string): { machine: string; prose: string } {
  const machine: string[] = [];
  const prose: string[] = [];
  let section: "machine" | "metadata" | "message" = "machine";
  for (const line of block.split("\n")) {
    if (/^\s*#/.test(line)) continue;
    if (/^ {4}metadata:\s*$/.test(line)) {
      section = "metadata";
      continue;
    }
    if (/^ {4}message: [>|]/.test(line)) {
      section = "message";
      continue;
    }
    if (section !== "machine" && line.trim() !== "" && !/^ {5,}/.test(line)) section = "machine";
    if (section === "metadata") continue;
    (section === "message" ? prose : machine).push(line);
  }
  const strip = (lines: string[]) => lines.join("\n").replace(/CWE-\d+/g, "");
  return { machine: strip(machine), prose: strip(prose) };
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
      ...splitRuleBody(block),
    });
  }
  return rules;
}

describe("#493/#975: harvey-* rule metadata.owasp matches OWASP's official 2021 CWE-to-category mapping", () => {
  const files = readNamesSafe(RULES_DIR).filter((f) => f.endsWith(".yml"));
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

// ─────────────────────────────────────────────────────────────────────────────
// #1521: bind a rule's DECLARED CWE to what the rule itself matches.
//
// The block above takes each rule's `cwe` AS GIVEN — it is the INPUT to that check, never its
// subject — so a rule declaring the wrong CWE, whose `owasp` is then correctly derived from that
// wrong CWE, passes by construction. That is worse than an ungated field: a reader sees a
// fail-loud green check and stops asking. Everything below is about the CWE itself.
//
// WHAT THIS ESTABLISHES, PLAINLY. Two checks, both keyed on rule id:
//
//   1. NAME <-> NUMBER. Every `cwe:` value in this repo is written `CWE-<n>: <name>`.
//      OFFICIAL_CWE_NAMES is MITRE's own Name field for <n>, transcribed from the published
//      catalogue (see its comment). A number/name pair that disagrees with MITRE fails. External
//      authority; not our judgement.
//
//   2. LABEL <-> RULE BODY. CWE_EVIDENCE gives each CWE a vocabulary drawn from that CWE's own MITRE
//      name and the defect it describes, and requires the rule's OWN body — its id, its patterns and
//      its client-facing message, with the `metadata:` block and bare CWE tokens removed — to
//      exhibit it. Swap a rule's CWE for a sibling in the same OWASP category and the sibling's
//      vocabulary is absent from the rule, so this check goes red where the OWASP check stays green.
//
// WHAT IT DOES NOT ESTABLISH — read this before quoting it as evidence:
//
//   - The vocabulary lists are HAND-WRITTEN BY US. They are anchored to MITRE's names, but choosing
//     which words stand for a CWE is our judgement, so check 2 is corroboration between two
//     artefacts we control, not independent measurement. CLAUDE.md's rule about an answer key we
//     wrote applies: it shows a label INCONSISTENT with its rule; it does not certify one correct.
//   - It reads the rule's SELF-DESCRIPTION as well as its machinery. A rule whose message is wrong
//     in the same direction as its CWE would pass on prose alone; the counted mitigation is
//     PROSE_ONLY below — the rules for which the evidence lands ONLY in the message. #1540 drove
//     that population from 41 to 0 by adding CWE_MACHINE_EVIDENCE, a second table keyed on the
//     SINK/IDIOM each weakness occurs on, checked against the machine half alone.
//   - Its discrimination is BOUNDED and MEASURED, not assumed: UNDISCRIMINATED names every rule for
//     which some same-category sibling CWE's vocabulary ALSO matches, so a swap to that specific
//     sibling would stay green. SINGLETON_CATEGORY names every rule whose CWE is the only one its
//     OWASP category has in use here, where "a swap within one category" has no target at all.
//     All three populations are asserted exactly, in both directions, so a drift fails the gate.
// ─────────────────────────────────────────────────────────────────────────────

// MITRE's own `Name` for each CWE the harvey-* rules declare. MEASURED 2026-07-30 against the
// published catalogue `cwec_v4.20.xml` (cwe.mitre.org/data/xml/cwec_latest.xml.zip, downloaded that
// day), by extracting `<Weakness ID Name>` for each id in use and diffing against the yaml. That run
// found THREE stale names, corrected in the same pass: CWE-113 ("HTTP Response Splitting" ->
// "HTTP Request/Response Splitting"), CWE-598 ("Use of GET Request Method With Sensitive Query
// Strings" -> "Use of HTTP Request With Sensitive Query String") and CWE-942 ("Permissive
// Cross-domain Policy" -> "Permissive Cross-domain Security Policy"). Falsifier: re-run that diff
// against a newer catalogue — MITRE renames weaknesses between releases and this table would
// otherwise go stale silently.
const OFFICIAL_CWE_NAMES: Record<string, string> = {
  "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "CWE-88": "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')",
  "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
  "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
  "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')",
  "CWE-116": "Improper Encoding or Escaping of Output",
  "CWE-117": "Improper Output Neutralization for Logs",
  "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-209": "Generation of Error Message Containing Sensitive Information",
  "CWE-235": "Improper Handling of Extra Parameters",
  "CWE-252": "Unchecked Return Value",
  "CWE-256": "Plaintext Storage of a Password",
  "CWE-295": "Improper Certificate Validation",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-321": "Use of Hard-coded Cryptographic Key",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
  "CWE-346": "Origin Validation Error",
  "CWE-347": "Improper Verification of Cryptographic Signature",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-353": "Missing Support for Integrity Check",
  "CWE-470": "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
  "CWE-489": "Active Debug Code",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-522": "Insufficiently Protected Credentials",
  "CWE-524": "Use of Cache Containing Sensitive Information",
  "CWE-540": "Inclusion of Sensitive Information in Source Code",
  "CWE-598": "Use of HTTP Request With Sensitive Query String",
  "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
  "CWE-602": "Client-Side Enforcement of Server-Side Security",
  "CWE-611": "Improper Restriction of XML External Entity Reference",
  "CWE-613": "Insufficient Session Expiration",
  // #1294 — MITRE names, read from each CWE's own page 2026-07-31.
  "CWE-636": "Not Failing Securely ('Failing Open')",
  "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
  "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
  "CWE-639": "Authorization Bypass Through User-Controlled Key",
  "CWE-668": "Exposure of Resource to Wrong Sphere",
  "CWE-693": "Protection Mechanism Failure",
  "CWE-770": "Allocation of Resources Without Limits or Throttling",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
  "CWE-862": "Missing Authorization",
  "CWE-863": "Incorrect Authorization",
  "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
  "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-942": "Permissive Cross-domain Security Policy with Untrusted Domains",
  "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
  "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
  "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
  "CWE-1204": "Generation of Weak Initialization Vector (IV)",
  "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
  "CWE-1333": "Inefficient Regular Expression Complexity",
};

// The vocabulary a rule must exhibit to be carrying the CWE it declares. Each is anchored to that
// CWE's MITRE name above and to the concrete API/idiom the weakness is about, NOT to any harvey rule
// id — the point is to be able to REJECT a rule, so a term that only ever appears in the rule we
// already assigned this CWE to would be worthless. Written deliberately narrow: a term broad enough
// to match every rule in an OWASP category discriminates nothing, and the UNDISCRIMINATED census
// below measures exactly how often that still happens.
const CWE_EVIDENCE: Record<string, RegExp> = {
  "CWE-22": /path traversal|zip-?slip|path\.(basename|join|resolve)/i,
  // "through a shell", not a bare `shell`: harvey-argument-injection's whole point is that there is
  // NO shell, and the bare term read that sentence as evidence for the shell-injection CWE.
  "CWE-78": /command injection|through a shell|child_process exec/i,
  "CWE-79": /\bXSS\b|cross-site scripting|innerHTML|dangerouslySetInnerHTML|__html|document\.write|autoescap|javascript:/i,
  "CWE-88": /argument injection|as an argv|argv-array element/i,
  "CWE-89": /\bSQL\b|parameterized quer/i,
  // #1273. Not a bare `filter`/`search`: those are the vocabulary of the PostgREST and Mongo rules
  // in the same category. CWE-90's own weakness is the LDAP query being rewritten.
  "CWE-90": /\bLDAP\b|search filter|bind DN/i,
  "CWE-95": /\beval\b|new Function/i,
  "CWE-113": /\bCRLF\b|CR\/LF|response splitting/i,
  // Not a bare escape/sanitize verb: every XSS rule's remediation sentence says "sanitize", which
  // made this row match 15 rules in other categories and discriminate nothing (MEASURED 2026-07-30).
  "CWE-116": /only the FIRST match|incomplete[ -]sanitiz|improper (encoding|escaping)|escaping of output/i,
  "CWE-117": /\blog(s|ged|ging|ger)?\b/i,
  // Requires an EXPOSURE word, which is what CWE-200's name is about. A bare `secret` also matched
  // every rule whose defect is a missing secret CHECK (CWE-862) — same noun, opposite weakness.
  "CWE-200": /expos|leak|sensitive|\bPII\b|serializ|to the browser bundle/i,
  "CWE-209": /error (object|message)|\.stack\b|stack trace|caught error/i,
  "CWE-235": /parameter pollution|repeated query parameter|Array\.isArray/i,
  "CWE-252": /discard|fire-and-forget|return value|no \.select|never complete/i,
  "CWE-256": /password/i,
  "CWE-295": /certificate|rejectUnauthorized/i,
  // Not a bare `plaintext`: ECB/CBC rules say "leaks plaintext structure" about a stored cipher,
  // which is CWE-327's weakness, not transmission in the clear.
  "CWE-319": /cleartext|unencrypted|\bHSTS\b|Strict-Transport|ws:\/\/|plain HTTP/i,
  "CWE-321": /hard-?coded (string|key|secret)|createHmac/i,
  // `createCipher\(` and not `createCipher`: the latter is a prefix of createCipheriv, the SAFE
  // API, so it matched the rule about a static IV passed to it (the #1355 self-match shape).
  "CWE-327": /\bMD5\b|\bSHA-?1\b|\b3?DES\b|\bRC[24]\b|Blowfish|\bECB\b|createCipher\(|authTag|broken|weak.{0,12}(cipher|hash|KDF)/i,
  "CWE-338": /pseudo-?random|\bPRNG\b|CSPRNG/i,
  "CWE-346": /\borigin\b/i,
  // Verification of a signature, not the noun on its own — "can forge valid signatures" is what a
  // hardcoded-key (CWE-321) or broken-hash (CWE-327) rule says about its own consequence.
  "CWE-347": /verif\w* the signature|signature verification|authentication tag|\balgorithms\b|algorithm-confusion|verify successfully/i,
  "CWE-352": /cross-site request forgery|CSRF (token|check)/i,
  "CWE-353": /integrity|\bSRI\b|subresource/i,
  // "dispatch against an allowlist" is the REMEDIATION every eval/code-injection rule recommends;
  // CWE-470 is about the dispatch being the defect.
  "CWE-470": /dispatched by a|unsafe reflection|invoke any property|before dispatch/i,
  "CWE-489": /NODE_ENV|debug|dev-mode/i,
  "CWE-502": /deserializ|unserialize/i,
  // A bare `token` is the noun of half the A04/A07 rules; CWE-522's weakness is where the
  // credential is KEPT.
  "CWE-522": /Web Storage|localStorage|sessionStorage|dangerouslyAllowBrowser|exposes the API key/i,
  "CWE-524": /\bcache/i,
  "CWE-540": /source ?map|client source|source code/i,
  "CWE-598": /sensitive query|secrets? in URLs?|as a URL query parameter/i,
  "CWE-601": /redirect/i,
  "CWE-602": /client-supplied|client-side|escalate/i,
  "CWE-611": /\bXXE\b|external entit|\bXML\b/i,
  "CWE-613": /expir|\bTTL\b|maxAge|long-lived/i,
  // #1294. The PERMISSIVE-DEFAULT-ON-ERROR direction, which is CWE-636's own weakness. A bare
  // `authoriz` was the vocabulary of the whole A01 category and is deliberately not here — that
  // breadth is exactly what let CWE-285 sit on a rate-limiter rule unchallenged.
  "CWE-636": /fails? OPEN|fail-open|failing closed|not failing securely/i,
  // #1273. `predicate` alone would also read as the SQL/PostgREST vocabulary; CWE-643 is the
  // XPath expression specifically.
  "CWE-643": /\bXPath\b|selectNodes|selectSingleNode/i,
  // The cookie's ATTRIBUTES, not the noun: a CORS rule that mentions "the victim's cookies" is not
  // reporting a missing Secure flag.
  "CWE-614": /HttpOnly|Set-Cookie|res\.cookie|SameSite/i,
  "CWE-639": /\bIDOR\b|\bBOLA\b|user-controlled key|owner\/tenant|enumerat/i,
  "CWE-668": /public: ?true|public bucket|readable by anyone|wrong sphere/i,
  "CWE-693": /\bCSP\b|nosniff|sandbox|defeats|mitigation|protection mechanism/i,
  "CWE-770": /\blimit\b|exhaust|throttl|unbounded/i,
  "CWE-798": /hard-?coded|service[-_ ]?role/i,
  "CWE-829": /require\(|dynamic (require|import)|which module is loaded|control sphere/i,
  // "with no <anything> check" also swallowed "no containment check" (path traversal) and "no
  // Origin/CSRF check" (CSRF); CWE-862's weakness is the missing AUTHORITY, named.
  "CWE-862": /(no|missing) (auth|authority|permission|shared-secret|CRON_SECRET)|unauthenticated|anonymous request/i,
  // A bare `privileg` matched any rule whose consequence is a privileged action; CWE-863 is
  // specifically the authenticated-but-under-authorized case.
  "CWE-863": /role\/permission check|function-level authorization|no role|lower-privilege/i,
  "CWE-915": /mass assignment|any column|field allowlist/i,
  // "a template engine with autoescaping on" is an XSS rule's REMEDIATION, not an SSTI defect.
  "CWE-917": /\bSSTI\b|as a server-side template|as template source/i,
  "CWE-918": /\bSSRF\b|server-side request forgery/i,
  "CWE-942": /\bCORS\b|Access-Control-Allow-Origin|cross-domain/i,
  "CWE-943": /\bNoSQL\b|PostgREST|query operator|filter clause|MongoDB/i,
  "CWE-1021": /X-Frame-Options|frame-ancestors|clickjack|\bframed\b/i,
  "CWE-1321": /prototype pollution|__proto__|Object\.prototype/i,
  // #1273. Anchored on the FORMULA half: a bare `CSV` also names the export format in rules that
  // have nothing to do with formula evaluation.
  "CWE-1236": /formula injection|as a formula|formula prefix|formula element/i,
  // #1294. Anchored on the IV itself. `$IV` in a pattern metavariable is not evidence of an
  // IV-PREDICTABILITY defect, which is why the prose terms carry it.
  "CWE-1204": /initialization vector|predictable iv|reusing an iv|the iv passed|weak.{0,4}iv/i,
  "CWE-1333": /\bReDoS\b|catastrophic backtrack|nested quantifier|regular expression complexity/i,
};

const NO_CATEGORY = "(no OWASP Top-10-2021 category)";

// #1540 — the MACHINE half's own vocabulary. CWE_EVIDENCE above is drawn from each CWE's MITRE
// NAME, and a rule's patterns are written in API idioms that name never uses: harvey-void-async
// matches `void $F(...)` for "Unchecked Return Value", harvey-mass-assignment matches a spread into
// `.insert()` for CWE-915. So 41 of 110 rules carried their CWE's vocabulary ONLY in the
// client-facing `message:` prose, and for those the label rested entirely on the rule's
// self-description — a message wrong in the same direction as the label passed green.
//
// This table is the second one #1540 asked for: per CWE, the SINK OR IDIOM a rule for that weakness
// executes. It is checked against `rule.machine` ONLY (id + match machinery, never the message), so
// a rule it corroborates is corroborated by what it RUNS, and machinery resists being written to
// flatter a label in the way prose does not.
//
// WRITING RULE, and it is what keeps this from being a rubber stamp: each entry is derived from the
// WEAKNESS — the API surface on which that weakness occurs — never from "whatever these rules
// happen to contain". `exec`/`child_process` is where OS command injection lives whoever wrote the
// rule; `focus-metavariable: $ARGS` is the argv-array half CWE-88 is about and CWE-78 is not;
// `ejs`/`Handlebars`/`pug` are template engines whether or not Harvey ever ships another SSTI rule.
// A CWE with no such surface gets NO row here and its rules stay in PROSE_ONLY with a reason.
//
// It feeds BOTH computations in the census below — the PROSE_ONLY population and the
// UNDISCRIMINATED one — because a signature that corroborates a label must also be able to
// MIScorroborate a sibling's, and hiding it from the second computation would understate the
// ambiguity it introduces.
const CWE_MACHINE_EVIDENCE: Record<string, RegExp> = {
  // Exposure: the process-global reads that ARE the exposed thing, plus the server-only boundary
  // marker whose absence is the defect.
  "CWE-200": /process\.env|process\.cwd\(|"server-only"/,
  // The caught error object serialised straight into a response body.
  "CWE-209": /\bjson\(\{? ?error\b/,
  // A repeated query parameter arrives as an ARRAY; the cast back to `string` is the tell.
  "CWE-235": /query\.\$\w+ as string/,
  // A return value that goes nowhere: `void` discards it, and the not-insides on assignment /
  // `return` / a chained `.select()` are the three places it would otherwise have been read.
  "CWE-252": /\bvoid \$\w+\(|pattern-not-inside: (return \.\.\.|\$A = \$B|\$Z\.select)/,
  // Transport security turned off at the client.
  "CWE-319": /ssl: ?false|rejectUnauthorized/,
  // The IV argument position of createCipheriv, which is where predictability is decided.
  "CWE-1204": /Buffer\.from\(\$IV/,
  // #1294 — the non-cryptographic RNG APIs themselves. `Math.random()` is JS's weak PRNG and
  // `pseudoRandomBytes` is node's; both are the surface on which this weakness occurs, whoever
  // wrote the rule.
  "CWE-338": /Math\.random\(\)|pseudoRandomBytes\(/,
  // #1294 — the permissive value returned from the failure branch, which IS the fail-open default.
  "CWE-636": /return \{ allowed: true \}/,
  // postMessage's second argument IS the target-origin check.
  "CWE-346": /postMessage\(/,
  // The verify/decode API surface, and the AEAD tag check that is the symmetric-crypto equivalent.
  "CWE-347": /jwt\.(decode|verify)\(|jsonwebtoken\.|jwtDecode|jwt_decode|return \$\w+\.update\(/i,
  // The Origin header read that a CSRF defence performs.
  "CWE-352": /\.get\("origin"\)|["']csrf/i,
  // Reflection: a member looked up by a computed key and immediately called.
  "CWE-470": /\$\w+\[\$\w+\]\(/,
  // Credential-looking names in a URL QUERY STRING, which is CWE-598's whole subject.
  "CWE-598": /\[\?&\]/,
  // Privilege flags taken from the client rather than decided on the server.
  "CWE-602": /is_\?(admin|superuser|root|owner)/i,
  // A shell-spawning API, or an argv API explicitly opted into a shell.
  "CWE-78": /\bexecS?y?n?c?\(|child_process\.exec(Sync)?\(|shell: ?true/,
  // The HTML/DOM write surfaces and the escaping APIs whose absence is the defect.
  "CWE-79": /DOMPurify|escapeHtml|sanitizeHtml|<a href=|<\$EL \{\.\.\.|window\.location|location\.href/,
  // The argv-ARRAY position, which is what separates CWE-88 from CWE-78's shell string.
  "CWE-88": /focus-metavariable: \$ARGS/,
  // A hard-coded literal standing in for a missing environment secret, or an admin/service client.
  "CWE-798": /env\.(get\(\.\.\.\)|\$\w+) *(\?\?|\|\|) *"|auth\.admin\.|service[-_ ]?role/i,
  // The authority calls a handler is missing: named in the pattern-not-inside that lets one pass.
  "CWE-862": /getServerSession|assertPermission|requirePermission|requireRole|query\.secret|supabaseAdmin\./,
  // The privileged surface, and the auth calls that establish identity but not ROLE.
  "CWE-863": /\*admin\*|\*privileged\*|requireAuth|verifyAccessToken|verifySession/,
  // A whole request body spread into a write.
  "CWE-915": /\$BODY|req\.body\)/,
  // The template engines on which server-side template injection occurs.
  "CWE-917": /(ejs|pug)\.(render|compile)\(|Handlebars\.compile\(\$\w+, \.\.\.\)|nunjucks\.renderString/i,
  // Next's image remotePatterns, the config surface whose wildcard host is the SSRF.
  "CWE-918": /remotePatterns|hostname: \$/,
  // The recursive-merge helpers through which a `__proto__` key reaches Object.prototype.
  "CWE-1321": /defaultsDeep|mergeWith\(|merge\(\$TARGET/,
  // #1273 — the CSV/spreadsheet SERIALIZERS are the surface on which a formula-prefixed cell is
  // written, whoever wrote the rule: csv-stringify's `stringify`, fast-csv's `writeToString`,
  // papaparse's `unparse`, SheetJS's sheet builders.
  "CWE-1236": /stringifySync\(|writeToString\(|writeToBuffer\(|unparse\(|_to_sheet\(/,
};

/** True when the rule's own machine half — never its prose — corroborates `cwe`. */
function machineCorroborates(cwe: string, machine: string): boolean {
  return CWE_EVIDENCE[cwe]!.test(machine) || (CWE_MACHINE_EVIDENCE[cwe]?.test(machine) ?? false);
}


/**
 * #1521 disclosure, measured by the census test below and asserted exactly in both directions.
 * These rules are inside the check but NOT protected against every same-category swap: at least one
 * sibling CWE's vocabulary also matches the rule's body, so relabelling to that sibling stays green.
 * A rule leaving this list (its vocabulary narrowed) fails as loudly as one joining it.
 */
const UNDISCRIMINATED: string[] = [
  // #1294, 2026-07-31. TWO rules LEFT this list and one joined, and the movement is the point.
  // `harvey-crypto-pseudorandombytes` (was "CWE-338 vs CWE-330") and `harvey-static-iv` (was
  // "CWE-329 vs CWE-327") left because the CWEs they were confusable WITH are no longer in use:
  // CWE-330 was the parent label #1294 corrected off harvey-insecure-random-token, and CWE-329 was
  // the CBC-restricted label corrected off harvey-static-iv itself. Fixing a mislabel therefore
  // shrank the ambiguity census, which is the census working as designed.
  "harvey-prod-sourcemaps", // CWE-540 vs CWE-200, of which MITRE makes 540 a descendant
  "harvey-public-bucket", // CWE-668 vs CWE-200 — both "exposure", differing in what is exposed
  "harvey-secret-in-url-param", // CWE-598 vs CWE-256: its sink list names `password` as a param
  // #1294 — and this one JOINED, which is the correction's honest cost. CWE-636 has no OWASP
  // Top-10-2021 category, so this rule moved out of A01 (where CWE-285's only sibling shapes were
  // authorization ones) into the NO_CATEGORY bucket, whose members share nothing but their absence
  // from OWASP's tables. A swap to the sibling named at runtime would stay green. Disclosed rather
  // than smoothed over: the CWE is now right and the intra-bucket discrimination is now weaker.
  "harvey-fail-open",
];

/**
 * #1521 disclosure. For these rules the declared CWE is the ONLY one its OWASP category has in use
 * across the harvey-* set, so "a swap within a single OWASP category" has no target — the check
 * still binds the label to the rule body, but the specific property #1521 asks for is vacuous here.
 */
const SINGLETON_CATEGORY: string[] = [
  "harvey-img-remotepatterns-wild", // A10 — CWE-918 is the only CWE it has
  "harvey-log-injection", // A09 — CWE-117 is the only CWE it has
  "harvey-ssrf-fetch", // A10 — CWE-918 is the only CWE it has
];

/**
 * #1521 disclosure, CLOSED by #1540 and kept as a ratchet. Rules whose declared CWE is corroborated
 * ONLY by the client-facing `message:` prose, never by the id or the match machinery — for those the
 * label rests on the rule's self-description, so a message written wrong in the same direction as
 * the label passes green.
 *
 * MEASURED: 41 of 110 rules on 2026-07-30, **0 of 110** on 2026-07-31, after CWE_MACHINE_EVIDENCE
 * gave each CWE the sink/idiom its rules actually execute. The list is asserted in BOTH directions,
 * so this is a ratchet rather than a milestone: a new rule whose patterns say nothing about its
 * label fails here and has to be added deliberately.
 *
 * A row added here must carry, in its own comment, the reason the machine half of that rule fails to
 * corroborate its label — the population is the disclosure, and an unexplained row is the thing this
 * count exists to prevent.
 */
const PROSE_ONLY: string[] = [];

describe("#1521: a rule's declared CWE is bound to the rule's own id, patterns and message", () => {
  const files = readNamesSafe(RULES_DIR).filter((f) => f.endsWith(".yml"));
  const rules = files.flatMap(parseRuleMetadata);
  const cweOf = (r: RuleMeta) => r.cwe![0]!.match(/^CWE-\d+/)![0];
  const categoryOf = (cwe: string) => OFFICIAL_CWE_TO_OWASP_2021[cwe] ?? NO_CATEGORY;
  const inUse = [...new Set(rules.map(cweOf))];

  it("both #1521 tables stay exhaustive over the CWEs actually in use", () => {
    const missing = inUse.filter((c) => !OFFICIAL_CWE_NAMES[c] || !CWE_EVIDENCE[c]);
    expect(missing, `CWEs a rule declares with no OFFICIAL_CWE_NAMES/CWE_EVIDENCE row: ${missing.join(", ")}`).toEqual([]);
    const known = [...new Set([...Object.keys(OFFICIAL_CWE_NAMES), ...Object.keys(CWE_EVIDENCE)])];
    const stale = known.filter((c) => !inUse.includes(c));
    expect(stale, `#1521 table rows for CWEs no rule declares any more: ${stale.join(", ")}`).toEqual([]);
  });

  it("the text the binding check reads cannot satisfy its own check", () => {
    const leaked = rules.filter((r) => /^\s+(cwe|owasp):/m.test(`${r.machine}\n${r.prose}`) || /CWE-\d/.test(`${r.machine}\n${r.prose}`));
    expect(leaked.map((r) => r.id), "a rule's own cwe/owasp label reached the subject text — the check would be self-satisfying").toEqual([]);
  });

  it.each(rules.map((r): [string, RuleMeta] => [r.id, r]))("%s: declares MITRE's official name for its CWE number", (_id, rule) => {
    const cweId = cweOf(rule);
    expect(rule.cwe![0], `${rule.id} (${rule.file}) declares ${cweId} under a name MITRE does not use`).toBe(`${cweId}: ${OFFICIAL_CWE_NAMES[cweId]}`);
  });

  it.each(rules.map((r): [string, RuleMeta] => [r.id, r]))("%s: its own id/patterns/message carry the vocabulary of the CWE it declares", (_id, rule) => {
    const cweId = cweOf(rule);
    const evidence = CWE_EVIDENCE[cweId]!;
    expect(
      evidence.test(`${rule.machine}\n${rule.prose}`),
      `${rule.id} (${rule.file}) declares ${cweId} — ${OFFICIAL_CWE_NAMES[cweId]} — but nothing in the rule's id, patterns or message reads as that weakness (looked for ${evidence}). Either the label is wrong or the rule describes what it matches in vocabulary this check does not know; check the label before widening CWE_EVIDENCE.`,
    ).toBe(true);
  });

  it("the census of what this check CANNOT discriminate matches its disclosure, exactly", () => {
    const undiscriminated = new Map<string, string[]>();
    const singleton: string[] = [];
    const proseOnly: string[] = [];
    for (const rule of rules) {
      const cweId = cweOf(rule);
      const siblings = inUse.filter((c) => c !== cweId && categoryOf(c) === categoryOf(cweId));
      if (siblings.length === 0) singleton.push(rule.id);
      // #1540: a sibling counts as confusable if EITHER vocabulary reaches this rule — the machine
      // signature is folded in here too, so the ambiguity it adds is disclosed rather than hidden.
      const confusable = siblings.filter((c) => CWE_EVIDENCE[c]!.test(`${rule.machine}\n${rule.prose}`) || (CWE_MACHINE_EVIDENCE[c]?.test(rule.machine) ?? false));
      if (confusable.length > 0) undiscriminated.set(rule.id, confusable);
      if (!machineCorroborates(cweId, rule.machine)) proseOnly.push(rule.id);
    }

    // Printed on every run: these populations ARE the disclosure, and a disclosure nobody reads is
    // the "unstated limitation reads as a clean bill of health" failure the not-assessed family
    // exists to prevent. Counts, never bare adjectives.
    console.log(
      [
        `#1521 CWE-binding census over ${rules.length} harvey-* rules (${inUse.length} distinct CWEs):`,
        `  discriminated against every same-category sibling: ${rules.length - undiscriminated.size}`,
        `  UNDISCRIMINATED (a swap to a named sibling would stay green): ${undiscriminated.size}`,
        ...[...undiscriminated].map(([id, c]) => `      ${id} <- also matches ${c.join(", ")}`),
        `  SINGLETON_CATEGORY (no same-category sibling exists; intra-category swap is vacuous): ${singleton.length}`,
        ...singleton.map((id) => `      ${id}`),
        `  PROSE_ONLY (evidence only in the message, not in the id/patterns): ${proseOnly.length}`,
        ...proseOnly.map((id) => `      ${id}`),
      ].join("\n"),
    );

    expect([...undiscriminated.keys()].sort(), "UNDISCRIMINATED drifted — a rule gained or lost same-category ambiguity; update the disclosure, do not silence it").toEqual([...UNDISCRIMINATED].sort());
    expect(singleton.sort(), "SINGLETON_CATEGORY drifted — a category gained or lost its second CWE").toEqual([...SINGLETON_CATEGORY].sort());
    expect(proseOnly.sort(), "PROSE_ONLY drifted — a rule's machine-level corroboration appeared or disappeared").toEqual([...PROSE_ONLY].sort());
  });

  // #1294 asked for "a gate that at least flags a rule whose CWE is a PARENT of one another rule
  // already uses for the same sink shape". This is it, and it is the specific hole that let
  // harvey-insecure-random-token carry CWE-330 while harvey-crypto-pseudorandombytes — four rules
  // away in the same file, same weakness, same determinacy — carried the child CWE-338. Every
  // pre-existing check passed that pair: 330 and 338 both map to A02, so the OWASP check could not
  // see it, and each rule's own vocabulary corroborated its own label.
  //
  // A parent and its child BOTH being in use is not automatically wrong — a rule set can
  // legitimately use the child where it applies and the parent where it does not. So the gate is a
  // ratchet, not a ban: every live pair carries a stated reason, and a pair that APPEARS or
  // DISAPPEARS fails. The proof it works is what is NOT below — `CWE-330 -> CWE-338` was live until
  // this change and is now absent, because the parent label was corrected off the rule.
  it("every parent/child CWE pair in simultaneous use is one that has been reasoned about", () => {
    const inUseSet = new Set(inUse);
    const live = CWE_PARENT_OF.filter(([parent, child]) => inUseSet.has(parent) && inUseSet.has(child)).map(([p, c]) => `${p} -> ${c}`);
    const detail = live.map((pair) => {
      const [p, c] = pair.split(" -> ") as [string, string];
      const named = (cwe: string) => rules.filter((r) => cweOf(r) === cwe).map((r) => r.id).join(", ");
      return `${pair}: parent on [${named(p)}], child on [${named(c)}]`;
    });
    console.log(`#1294 parent/child CWE pairs live in the rule set: ${live.length}\n${detail.map((d) => `      ${d}`).join("\n")}`);
    expect(live.sort(), "a parent CWE and its MITRE child are both in use and the pair is not in PARENT_CHILD_REASONED — the parent label is under-specific unless there is a stated reason").toEqual([...Object.keys(PARENT_CHILD_REASONED)].sort());
  });
});

/**
 * #1294 — the parent/child CWE pairs that are simultaneously in use ON PURPOSE, each with the reason
 * the parent is not the lazy label. Asserted EXACTLY, in both directions: a new pair fails as an
 * under-specific label, and a pair that stops being live fails as a stale disclosure.
 *
 * `CWE-330 -> CWE-338` is deliberately absent. It was live until 2026-07-31 and was the defect
 * #1294 found: `harvey-insecure-random-token` carried the parent while `harvey-crypto-
 * pseudorandombytes` carried the child for the same weakness. Re-adding CWE-330 to any rule fails
 * this test, which is the negative control.
 */
const PARENT_CHILD_REASONED: Record<string, string> = {
  "CWE-200 -> CWE-540":
    "harvey-prod-sourcemaps carries the CHILD (source-code inclusion) because that is exactly what productionBrowserSourceMaps ships. The five CWE-200 rules expose something that is not source code — process.env in a response body, a missing server-only boundary, SELECT * PII — so the parent is the specific label there, not a fallback.",
  "CWE-668 -> CWE-200":
    "harvey-public-bucket carries the PARENT deliberately: `public: true` proves a RESOURCE reached the wrong sphere and proves nothing about whether the bucket holds sensitive data, which is what the child asserts. Claiming CWE-200 would be an over-claim about the contents.",
};

/**
 * #1294 — MITRE ChildOf relations among the CWEs this rule set has used, read from each child's own
 * cwe.mitre.org page. Only pairs where BOTH ends have appeared in a harvey-* rule are listed: the
 * table exists to catch the under-specific-label mistake, not to mirror the CWE catalogue.
 *
 * `[parent, child]`. CWE-330/CWE-338 is the pair #1294 found live; the other two are the
 * relationships already named in the UNDISCRIMINATED comments above, written down here so the check
 * can act on them instead of a reader having to notice.
 */
const CWE_PARENT_OF: readonly (readonly [string, string])[] = [
  ["CWE-330", "CWE-338"], // Use of Insufficiently Random Values -> Cryptographically Weak PRNG
  ["CWE-200", "CWE-540"], // Exposure of Sensitive Information -> Inclusion of Sensitive Info in Source Code
  ["CWE-284", "CWE-285"], // Improper Access Control -> Improper Authorization
  ["CWE-707", "CWE-74"], // Improper Neutralization -> Injection
  ["CWE-74", "CWE-89"], // Injection -> SQL Injection
  ["CWE-74", "CWE-79"], // Injection -> Cross-site Scripting
  ["CWE-74", "CWE-78"], // Injection -> OS Command Injection
  ["CWE-74", "CWE-90"], // Injection -> LDAP Injection
  ["CWE-74", "CWE-643"], // Injection -> XPath Injection
  ["CWE-94", "CWE-95"], // Improper Control of Generation of Code -> Eval Injection
  ["CWE-668", "CWE-200"], // Exposure of Resource to Wrong Sphere -> Exposure of Sensitive Information
];
