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
//   - It reads the rule's SELF-DESCRIPTION. A rule whose message is wrong in the same direction as
//     its CWE passes. The counted mitigation is PROSE_ONLY below — the rules for which the evidence
//     lands only in the prose and not in the id/patterns.
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
  "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
  "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')",
  "CWE-116": "Improper Encoding or Escaping of Output",
  "CWE-117": "Improper Output Neutralization for Logs",
  "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-209": "Generation of Error Message Containing Sensitive Information",
  "CWE-235": "Improper Handling of Extra Parameters",
  "CWE-252": "Unchecked Return Value",
  "CWE-256": "Plaintext Storage of a Password",
  "CWE-285": "Improper Authorization",
  "CWE-295": "Improper Certificate Validation",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-321": "Use of Hard-coded Cryptographic Key",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-329": "Generation of Predictable IV with CBC Mode",
  "CWE-330": "Use of Insufficiently Random Values",
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
  // A bare `authoriz` is the vocabulary of the whole A01 category; CWE-285's own weakness is the
  // fail-open direction of the decision.
  "CWE-285": /fails? OPEN|fail-open|failing closed|improper authoriz/i,
  "CWE-295": /certificate|rejectUnauthorized/i,
  // Not a bare `plaintext`: ECB/CBC rules say "leaks plaintext structure" about a stored cipher,
  // which is CWE-327's weakness, not transmission in the clear.
  "CWE-319": /cleartext|unencrypted|\bHSTS\b|Strict-Transport|ws:\/\/|plain HTTP/i,
  "CWE-321": /hard-?coded (string|key|secret)|createHmac/i,
  // `createCipher\(` and not `createCipher`: the latter is a prefix of createCipheriv, the SAFE
  // API, so it matched the rule about a static IV passed to it (the #1355 self-match shape).
  "CWE-327": /\bMD5\b|\bSHA-?1\b|\b3?DES\b|\bRC[24]\b|Blowfish|\bECB\b|createCipher\(|authTag|broken|weak.{0,12}(cipher|hash|KDF)/i,
  // `$IV` in a pattern metavariable is not evidence of an IV-PREDICTABILITY defect.
  "CWE-329": /initialization vector|predictable iv|reusing an iv|the iv passed/i,
  "CWE-330": /Math\.random|insufficiently random|not cryptographically secure/i,
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
  "CWE-1333": /\bReDoS\b|catastrophic backtrack|nested quantifier|regular expression complexity/i,
};

const NO_CATEGORY = "(no OWASP Top-10-2021 category)";

/**
 * #1521 disclosure, measured by the census test below and asserted exactly in both directions.
 * These rules are inside the check but NOT protected against every same-category swap: at least one
 * sibling CWE's vocabulary also matches the rule's body, so relabelling to that sibling stays green.
 * A rule leaving this list (its vocabulary narrowed) fails as loudly as one joining it.
 */
const UNDISCRIMINATED: string[] = [
  "harvey-crypto-pseudorandombytes", // CWE-338 vs CWE-330, of which MITRE makes 338 a child
  "harvey-prod-sourcemaps", // CWE-540 vs CWE-200, of which MITRE makes 540 a descendant
  "harvey-public-bucket", // CWE-668 vs CWE-200 — both "exposure", differing in what is exposed
  "harvey-secret-in-url-param", // CWE-598 vs CWE-256: its sink list names `password` as a param
  "harvey-static-iv", // CWE-329 vs CWE-327 — a predictable IV is a way of using the cipher badly
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
 * #1521 disclosure. Rules whose declared CWE's vocabulary is found ONLY in the client-facing
 * `message:` prose, never in the id or the match machinery. For these the binding rests entirely on
 * the rule's self-description, so a message written wrong in the same direction as the label passes.
 * Everything NOT listed here is corroborated by the id/patterns as well.
 */
const PROSE_ONLY: string[] = [
  "harvey-aead-decipher-no-final",
  "harvey-argument-injection",
  "harvey-auth-admin-in-client",
  "harvey-authed-no-role-check",
  "harvey-client-trusted-role",
  "harvey-command-injection",
  "harvey-cron-no-secret",
  "harvey-csrf-missing",
  "harvey-db-error-disclosure",
  "harvey-dynamic-dispatch",
  "harvey-edgefn-secret-fallback",
  "harvey-hpp-query-cast",
  "harvey-href-js-url",
  "harvey-html-template-literal",
  "harvey-img-remotepatterns-wild",
  "harvey-internal-state-response",
  "harvey-isr-revalidate-nosecret",
  "harvey-jsx-prop-spread-injection",
  "harvey-jwt-decode-noverify",
  "harvey-jwt-decode-render",
  "harvey-jwt-verify-noalg",
  "harvey-lib-command-injection",
  "harvey-mass-assignment",
  "harvey-mass-assignment-bare",
  "harvey-missing-server-only",
  "harvey-nextconfig-env-secret",
  "harvey-node-secret-fallback",
  "harvey-open-url-sink",
  "harvey-pg-mass-assignment",
  "harvey-pg-ssl-disabled",
  "harvey-postmessage-wildcard",
  "harvey-prototype-pollution",
  "harvey-route-noauth",
  "harvey-secret-in-url-param",
  "harvey-server-action-noauth",
  "harvey-spawn-shell-true",
  "harvey-static-iv",
  "harvey-template-injection",
  "harvey-unchecked-mutation",
  "harvey-void-async",
  "harvey-zero-row-update",
];

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
      const confusable = siblings.filter((c) => CWE_EVIDENCE[c]!.test(`${rule.machine}\n${rule.prose}`));
      if (confusable.length > 0) undiscriminated.set(rule.id, confusable);
      if (!CWE_EVIDENCE[cweId]!.test(rule.machine)) proseOnly.push(rule.id);
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
});
