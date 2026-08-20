import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readNamesSafe } from "../../../fs-walk.js";
import { fileURLToPath } from "node:url";
import { parse, stringify } from "yaml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// #1221: the taint SOURCE vocabulary drifted apart rule by rule. Twelve rules carried a
// byte-identical hand-copied source list and the widenings of #570/#984/#987/#601 landed on some
// copies and not others — MEASURED 2026-07-27 (semgrep 1.164.0), 17 of 21 server-side taint rules
// could not see `await req.json()` and 19 of 21 could not see `searchParams.get()`.
//
// The fix is a YAML anchor per file. Anchors resolve at parse time and do not cross documents, so
// the block is physically duplicated — which is the same failure mode one indirection later unless
// something fails loud. These two tests are that something: the copies must stay identical, and a
// server-side taint rule must either USE the anchor or be listed below with a reason. A new rule
// that hand-rolls its own source list is the defect, and it now cannot land silently.

const RULES_DIR = dirname(fileURLToPath(import.meta.url));

// The executable half of this file needs the real binary. `pnpm verify`'s CI job deliberately does
// not install it, so the block below skips there — and a skipIf is a silent pass by design, which is
// this repo's own worst failure shape. Two things close that: `heavy CLI tests (shard 3/3)` runs this
// file with HARVEY_REQUIRE_SEMGREP=1, which turns a missing binary into a red run instead of a skip;
// and the two mustCatch corpus rows (P-RSC-ARROW-TYPED-BINDING / P-RSC-ARROW-UNTYPED-BINDING) gate
// the same arms through `validate-calibration` in shard 1.
const SEMGREP_PRESENT = ((): boolean => {
  try {
    execFileSync("which", ["semgrep"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();
if (process.env.HARVEY_REQUIRE_SEMGREP === "1" && !SEMGREP_PRESENT) {
  throw new Error("HARVEY_REQUIRE_SEMGREP=1 but semgrep is not on PATH — the pattern-match block would have skipped silently");
}
if (!SEMGREP_PRESENT) {
  console.warn(
    "⚠ shared-sources.test.ts: semgrep absent — the block that EXECUTES the canonical source block against probes did not run.\n" +
      "  It is the only check here that can catch a pattern that is present but inert (#1544). CI runs it in `heavy CLI tests (shard 3/3)`.",
  );
}

const probeDirs: string[] = [];
afterAll(() => {
  for (const d of probeDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// Rules that deliberately do NOT take the canonical block. Each is a judgment about what the rule
// is ABOUT, not an oversight — an unexplained absence from this map is what the test catches.
const NARROW_BY_DESIGN: Record<string, string> = {
  "harvey-dangerously-set-inner-html": "client-side render sources (router.query/useSearchParams), not server request accessors",
  "harvey-select-star-pii": "the source is a DB projection, not the request",
  "harvey-dangerously-set-inner-html-stored": "stored-XSS: the source is a DB read, not the request",
  "harvey-cors-reflected-origin-object": "the Origin header specifically — a wider source set would change the bug class",
  "harvey-mass-assignment": "body-only by design: the bug is spreading the whole body, so a header or query source is not this weakness",
  "harvey-idor-param": "an IDOR source is an IDENTIFIER (query/route param/searchParams), so cookies and headers are out of class — #1221's two missing shapes were added to its own list instead",
  "harvey-prototype-pollution": "a recursive merge pollutes via KEYS, so an attacker-controlled STRING is inert — route params and searchParams.get are out of class, and URLSearchParams/cookies()/headers() keep their entries in internal slots a deep merge never walks (#1224)",
  "harvey-lib-path-traversal": "library entry points (exported function parameters), not request accessors",
  "harvey-lib-command-injection": "library entry points",
  "harvey-lib-code-injection": "library entry points",
};

// Rules whose source list is narrower for no RECORDED reason — measured drift awaiting a per-rule
// judgment (#1224). Deliberately a separate map from NARROW_BY_DESIGN: calling an unexamined gap
// "by design" is how a gap stops being outstanding work without anyone deciding it should.
// The client sink rules take the OTHER shared block (#1223, xss.yml's `*dom_source`) — a DOM
// source is a different vocabulary, not a narrower one, so it gets its own anchor and its own
// coverage assertion rather than an exemption.
const CLIENT_RULES = [
  "harvey-dom-innerhtml",
  "harvey-document-write",
  "harvey-href-js-url",
  "harvey-open-url-sink",
  "harvey-set-attribute-xss",
];

// Rules whose source list is narrower for no RECORDED reason — measured drift awaiting a per-rule
// judgment. Deliberately a separate map from NARROW_BY_DESIGN: calling an unexamined gap "by
// design" is how a gap stops being outstanding work without anyone deciding it should. #1224
// emptied it, and it is kept as the landing slot for the next unexamined narrowing.
const PENDING_JUDGMENT: Record<string, string> = {};

// #1708: a DIFFERENT judgment from the two maps above. NARROW_BY_DESIGN/PENDING_JUDGMENT decide
// whether a rule uses the canonical block AT ALL; the two final maps below decide, for every rule that
// already does, whether it should ALSO take a client source block — i.e. whether a CLIENT component reading
// a URL param and reaching this rule's sink is the same bug class as the server-request case. Every
// rule that consumes `*request_source` is judged into exactly one of the two final dispositions;
// leaving one
// unjudged is what "judges every request-source rule" below exists to catch.
//
// IN_CLASS: the sink is a client-reachable call (chiefly supabase-js, which ships in the browser
// bundle and is idiomatically called directly from a "use client" component) — a client source
// block is added alongside `*request_source`.
//
// There are TWO such blocks and the difference is deliberate, not drift. A rule whose sink exists
// only in a browser takes xss.yml's `*dom_source`, which can afford receiver-agnostic `.get()` and
// `.query.` arms. A rule whose sink runs on BOTH sides takes injection.yml's `*client_url_source`,
// which binds those receivers — the bare arms fire on every server-side Map/Headers/config `.get()`
// and on Drizzle's `db.query.<table>`, two of them landing in the ERROR/HIGH graded free count.
const CLIENT_SOURCE_ANCHORS = ["*dom_source", "*client_url_source"];
const takesClientSource = (rule: Rule | undefined): boolean =>
  CLIENT_SOURCE_ANCHORS.some((anchor) => rule?.sources.includes(anchor) === true);

const CLIENT_URL_PARAM_COMPANIONS: Record<string, { id: string; severity: string; confidence: string; harveySeverity: string }> = {
  "harvey-code-injection-eval": {
    id: "harvey-code-injection-eval-client-url",
    severity: "WARNING",
    confidence: "MEDIUM",
    harveySeverity: "Medium",
  },
  "harvey-csv-formula-injection": {
    id: "harvey-csv-formula-injection-client-url",
    severity: "WARNING",
    confidence: "MEDIUM",
    harveySeverity: "Medium",
  },
};

const CLIENT_URL_PARAM_IN_CLASS: Record<string, string> = {
  "harvey-path-traversal": "the Supabase Storage sink (storage.from(...).upload/download) is a supabase-js call reachable from a client component — the real instance that opened #1708 (carbon's JobBillOfProcess.tsx, useUrlParams() -> storage upload). Takes *client_url_source: the same rule's fs and res.sendFile sinks are server-only, so the receiver has to be bound",
  "harvey-sql-injection-rpc": "the sink is a supabase-js .rpc(...) call, callable directly from a client component with no server hop. Takes *client_url_source — this rule is ERROR/HIGH, so an unbound receiver lands false positives in the graded free count",
  "harvey-postgrest-filter-injection": "the sink (.or/.filter/.textSearch) is the same supabase-js client object as the two rules above; takes *client_url_source for the same reason",
  "harvey-jsx-prop-spread-injection": "already carries both *dom_source and *request_source since #1237 — its sink spans both sides of the server/client boundary by design",
  "harvey-code-injection-eval": "eval/new Function exist in the browser, but browser-local execution is Medium/review rather than server RCE; implemented by the distinct harvey-code-injection-eval-client-url companion",
  "harvey-csv-formula-injection": "PapaParse and SheetJS/XLSX run in browser export flows while csv-stringify, fast-csv and json2csv are Node-only; implemented by the sink-limited harvey-csv-formula-injection-client-url companion",
  "harvey-dynamic-dispatch": "computed method dispatch is client-reachable and remains at the existing WARNING/MEDIUM/Harvey Medium review band; takes the receiver-bound *client_url_source in-place",
};

// OUT_OF_CLASS: the sink is a server-only object or a Node-only library with no browser build, so
// widening the source leaves a client component with no path to it.
const CLIENT_URL_PARAM_OUT_OF_CLASS: Record<string, string> = {
  "harvey-sql-injection-template": "sink is a raw-SQL driver .query() call — a Node DB driver, never bundled for or callable from the browser",
  "harvey-open-redirect": "sink is a server response object (res.redirect/NextResponse.redirect/res.writeHead/res.setHeader Location/res.location) — there is no response object in a client component",
  "harvey-ssrf-fetch": "SSRF is defined by a SERVER crossing an internal-network trust boundary; a client component's own fetch() is the user's browser making the request, not the server, so the bug class does not apply",
  "harvey-command-injection": "sink is child_process exec/execSync — a Node API absent from the browser",
  "harvey-argument-injection": "sink is child_process execFile/spawn — a Node API absent from the browser",
  "harvey-nosql-injection": "sink is a Mongo/Mongoose query operator — a server-side ODM, never bundled for the browser",
  "harvey-unsafe-deserialization": "sink is node-serialize's unserialize()/$S.unserialize() — a Node-only package with no browser build",
  "harvey-template-injection": "SSTI is inherently server-side template rendering; no server template engine (EJS/Pug/Nunjucks) runs in a browser",
  "harvey-xpath-injection": "the message and CWE frame this against an XML-backed credential STORE reached server-side; the $D.evaluate arm could syntactically match document.evaluate() on the page's own DOM, but that has no separate store to query, so it is not the same bug shape reached client-side",
  "harvey-ldap-injection": "requires the file to import ldapjs/ldapts — Node-only LDAP client libraries absent from the browser",
  "harvey-log-injection": "the CWE-117 threat model is forging entries in a SERVER log a SIEM/audit pipeline parses; console.* in a client component writes to the user's own browser devtools console, which nothing downstream parses",
  "harvey-dynamic-require": "sink is require($X) — CommonJS require is not a runtime capability of client-bundled code",
  "harvey-html-template-literal": "sink is res.send() — a server response object, absent from a client component",
  "harvey-crlf-header-injection": "sink is res.setHeader — a server response object; there is no HTTP response to set headers on from a client component",
  "harvey-xxe-parse": "browser-native DOMParser.parseFromString does not fetch or expand external DTD entities, so a client URL value is outside this XXE threat model; server-side DOMParser polyfills and libxmljs request flows remain covered",
};

interface Rule {
  file: string;
  id: string;
  taint: boolean;
  sources: string[];
  sinks: unknown[];
  sanitizers: unknown[];
  severity: string;
  confidence: string;
  harveySeverity: string;
  message: string;
}

function parseRules(file: string): Rule[] {
  const doc = parse(readFileSync(join(RULES_DIR, file), "utf8")) as Record<string, unknown>;
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  const sourceAnchors = [
    ["*request_source", doc["x-request-source"]],
    ["*dom_source", doc["x-dom-source"]],
    ["*client_url_source", doc["x-client-url-source"]],
  ] as const;

  return rules.flatMap((candidate): Rule[] => {
    if (candidate === null || typeof candidate !== "object") return [];
    const rule = candidate as Record<string, unknown>;
    if (typeof rule.id !== "string") return [];
    const sourceEntries = Array.isArray(rule["pattern-sources"]) ? rule["pattern-sources"] : [];
    const metadata = rule.metadata !== null && typeof rule.metadata === "object" ? (rule.metadata as Record<string, unknown>) : {};
    return [{
      file,
      id: rule.id,
      taint: rule.mode === "taint",
      sources: sourceAnchors.filter(([, value]) => value !== undefined && sourceEntries.some((entry) => entry === value)).map(([name]) => name),
      sinks: Array.isArray(rule["pattern-sinks"]) ? rule["pattern-sinks"] : [],
      sanitizers: Array.isArray(rule["pattern-sanitizers"]) ? rule["pattern-sanitizers"] : [],
      severity: typeof rule.severity === "string" ? rule.severity : "",
      confidence: typeof metadata.confidence === "string" ? metadata.confidence : "",
      harveySeverity: typeof metadata.harveySeverity === "string" ? metadata.harveySeverity : "",
      message: typeof rule.message === "string" ? rule.message : "",
    }];
  });
}

function patternStrings(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(patternStrings);
  if (value === null || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => key === "pattern" && typeof child === "string" ? [child] : patternStrings(child));
}

function ruleFiles(): string[] {
  return readNamesSafe(RULES_DIR).filter((f) => f.endsWith(".yml"));
}

// The anchor definition block, from its key to the first line at column 0 that follows it. Takes
// the anchor's declaration line so the same function serves x-request-source (#1221) AND
// x-dom-source (#1223/#1708) — a second anchor duplicated across files is the identical drift risk
// one level over, and #1708 gave injection.yml its own copy of x-dom-source for the first time.
function anchorBlock(file: string, declLine: string): string | undefined {
  const text = readFileSync(join(RULES_DIR, file), "utf8");
  const start = text.indexOf(`${declLine}\n`);
  if (start === -1) return undefined;
  const rest = text.slice(start);
  const end = /\n(?=\S)/.exec(rest.slice(`${declLine}\n`.length));
  const block = end === null ? rest : rest.slice(0, `${declLine}\n`.length + end.index);
  return block.trimEnd();
}

describe("canonical request-taint source block (#1221)", () => {
  it("is byte-identical in every file that declares it", () => {
    const declared = ruleFiles()
      .map((f) => [f, anchorBlock(f, "x-request-source: &request_source")] as const)
      .filter((pair): pair is readonly [string, string] => pair[1] !== undefined);

    expect(declared.length).toBeGreaterThan(1);
    const [firstFile, canonical] = declared[0]!;
    for (const [file, block] of declared.slice(1)) {
      expect(block, `${file}'s copy of the canonical source block has drifted from ${firstFile}'s`).toBe(canonical);
    }
  });

  it("carries the App Router shapes the drift had lost", () => {
    const canonical = anchorBlock("base.yml", "x-request-source: &request_source");
    expect(canonical).toBeDefined();
    for (const pattern of ["await $REQ.json()", "$U.searchParams.get(...)", "$U.searchParams"]) {
      expect(canonical, `the canonical block lost ${pattern} — the shape #1221 exists to add`).toContain(pattern);
    }
    // A bare `$SP.get(...)` was MEASURED to fire on Map/Headers/config/FormData `.get()` even
    // behind ssrf-fetch's http-client guard. It must never re-enter the shared block.
    expect(canonical).not.toContain("- pattern: $SP.get(...)");
  });

  it("carries the Server Component request props, guarded by the not-inside that makes them safe", () => {
    const canonical = anchorBlock("base.yml", "x-request-source: &request_source");
    for (const pattern of ["$RSCPROP.$RSCFIELD", "await $RSCPROP", "^(params|searchParams)$"]) {
      expect(canonical, `the canonical block lost ${pattern} — the RSC page shape #1240 exists to add`).toContain(pattern);
    }
    // Without this exclusion the name-constrained access fired on three of five benign probes
    // (options bag, locally-built URLSearchParams, Map alias). Dropping it silently re-opens them.
    expect(canonical, "the `$RSCPROP = ...` not-inside is what makes a NAME-matched source safe — it must not be dropped").toContain("$RSCPROP = ...");
  });

  // #1544: the block used to reach the name WITHOUT its binding form, on a recorded semgrep OSS
  // capability bound that was ASSUMED and measured false. The binding is now a required conjunct:
  // an access is a request source only inside a scope that destructures the name out of an object.
  // Dropping it is what re-opens the three shapes N-RSC-PARAM-NON-PARAM-BINDING covers, none of
  // which the not-insides above can see — a for-of loop variable, an array destructure, an import.
  it("requires the RSC prop to be BOUND BY DESTRUCTURING, not merely named", () => {
    const canonical = anchorBlock("base.yml", "x-request-source: &request_source")!;
    for (const pattern of [
      "function $RSCFN(..., { ..., $RSCBIND, ... }, ...) { ... }",
      "function $RSCFN(..., { ..., $RSCBIND, ... }: $T, ...) { ... }",
      "(..., { ..., $RSCBIND, ... }, ...) => ...",
      "(..., { ..., $RSCBIND, ... }: $T, ...) => ...",
      "(..., { ..., $RSCBIND, ... }, ...) => { ... }",
      "(..., { ..., $RSCBIND, ... }: $T, ...) => { ... }",
      "const { ..., $RSCBIND, ... } = $SRC;",
    ]) {
      expect(
        canonical,
        `the canonical block lost the \`${pattern}\` binding shape — without every one of them the ` +
          "source is name-only again for that spelling (#1544). The typed and untyped spellings are " +
          "both needed: the pattern must carry the annotation to reach a typed parameter.",
      ).toContain(pattern);
    }
    // $RSCBIND is deliberately NOT unified with $RSCPROP: a metavariable unified with the outer
    // access stops at the first field of a multi-key object pattern, so `{ children, params }` — an
    // App Router layout — went unmatched. It is regex-filtered to the same names instead.
    expect(canonical, "the $RSCBIND binding must be constrained to the RSC prop names").toMatch(
      /metavariable: \$RSCBIND\n\s+regex: \^\(params\|searchParams\)\$/,
    );
  });

  // EVERY ASSERTION ABOVE IS A STRING COMPARISON, and #1544 proved that is not enough. Its first cut
  // shipped `(..., { ..., $RSCBIND, ... }, ...) => ...`, which the test above happily confirmed was
  // PRESENT — while MEASURED 2026-07-31 (semgrep 1.164.0) that spelling matches an EXPRESSION-bodied
  // arrow only and returns 0 on `({ params }) => { … }`, the only spelling the real world uses (40
  // occurrences in 33 files across the 17 pinned corpus repos, against ZERO of the expression form).
  // A pattern can be present and inert. So the block is now EXECUTED against probes, extracted from
  // base.yml rather than retyped, so a stale or gutted arm fails here and not in a client's report.
  describe.skipIf(!SEMGREP_PRESENT)("the canonical block, EXECUTED against probes rather than grepped (#1544)", () => {
    // Written as source, not as an assertion about source: every file here is a real binding shape.
    const MUST_MATCH: Record<string, string> = {
      "fn-untyped.tsx": "export default async function Page({ params }) {\n  return fetch(`/x/${params.id}`);\n}\n",
      "fn-typed.tsx": "export default async function Page({ params }: P) {\n  return fetch(`/x/${params.id}`);\n}\n",
      "fn-layout-multikey.tsx": "export default function Layout({ children, params }: P) {\n  return fetch(`/x/${params.id}`);\n}\n",
      "arrow-untyped-expr.ts": "export const a = ({ params }) => fetch(`/x/${params.id}`);\n",
      "arrow-typed-expr.ts": "export const b = ({ params }: P) => fetch(`/x/${params.id}`);\n",
      // The two the first cut of #1544 could not see. THE BODIES MUST HOLD MORE THAN ONE STATEMENT.
      // MEASURED 2026-07-31 while proving this test's failing direction: with the `=> { ... }` arm
      // deleted, a probe whose body is a bare `return …` STILL MATCHED — `=> ...` reaches a
      // single-statement block. A one-line body therefore fails to separate the two spellings, and a
      // probe set written that way is what let the regression ship. That is #1544's own lesson
      // reproduced one layer down, inside the test written to catch it.
      "arrow-untyped-block.ts": "export const loader = async ({ params }) => {\n  const res = await fetch(`/x/${params.id}`);\n  return res.json();\n};\n",
      "arrow-typed-block.ts": "export const c = async ({ params }: P) => {\n  const res = await fetch(`/x/${params.id}`);\n  return res.json();\n};\n",
      "in-body-destructure.ts": "export function Page(props) {\n  const { params } = props;\n  return fetch(`/x/${params.id}`);\n}\n",
    };

    // The shapes the binding requirement exists to SPARE. Each was measured firing before #1544.
    const MUST_NOT_MATCH: Record<string, string> = {
      "benign-plain-param.ts": "export function runJob(params) {\n  return fetch(`/x/${params.dir}`);\n}\n",
      "benign-plain-param-arrow.ts": "export const run = (params) => {\n  return fetch(`/x/${params.dir}`);\n};\n",
      "benign-loop-var.ts": "export function q(rows) {\n  for (const params of rows) fetch(`/x/${params.id}`);\n}\n",
      "benign-array-destructure.ts": "export function h() {\n  const [params] = useUrlParams();\n  return fetch(`/x/${params.id}`);\n}\n",
      "benign-import-const.ts": 'import { params } from "./config";\nexport const u = () => fetch(`/x/${params.id}`);\n',
      "benign-local-assign.ts": "export function s(q) {\n  const searchParams = new URLSearchParams(q);\n  return fetch(`/x/${searchParams.get(\"a\")}`);\n}\n",
    };

    let matched: Set<string>;

    beforeAll(() => {
      const dir = mkdtempSync(join(tmpdir(), "harvey-shared-source-probe-"));
      probeDirs.push(dir);
      for (const [name, body] of Object.entries({ ...MUST_MATCH, ...MUST_NOT_MATCH })) {
        writeFileSync(join(dir, name), body);
      }

      // The block itself, resolved by the YAML parser — anchors resolve at parse time, so this is the
      // same mapping every rule below receives. Retyping it here would test a copy, not the block.
      const doc = parse(readFileSync(join(RULES_DIR, "base.yml"), "utf8")) as Record<string, unknown>;
      const block = doc["x-request-source"];
      expect(block, "base.yml no longer declares x-request-source").toBeDefined();
      const rulePath = join(dir, "probe-rule.yml");
      writeFileSync(
        rulePath,
        stringify({
          rules: [{ id: "probe-request-source", languages: ["javascript", "typescript"], severity: "INFO", message: "probe", ...(block as object) }],
        }),
      );

      const out = execFileSync(
        "semgrep",
        ["--config", rulePath, "--metrics=off", "--no-git-ignore", "--json", "-j", "1", "--timeout", "0", dir],
        { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
      );
      const parsed = JSON.parse(out) as { results: { path: string }[]; errors: unknown[] };
      // A config semgrep could not load reports ZERO findings and every MUST_NOT assertion passes —
      // the silent-zero this whole file exists to prevent, one level down.
      expect(parsed.errors, "semgrep reported config/parse errors, so a zero here means nothing").toEqual([]);
      matched = new Set(parsed.results.map((r) => r.path.split("/").pop()!));
    });

    it.each(Object.keys(MUST_MATCH))("matches %s", (name) => {
      expect(
        matched.has(name),
        `the canonical block did not match ${name}. A pattern-inside arm is missing or inert — the ` +
          "shipped-and-silent state #1544's first cut was in for the two block-bodied arrow spellings.",
      ).toBe(true);
    });

    it.each(Object.keys(MUST_NOT_MATCH))("spares %s", (name) => {
      expect(
        matched.has(name),
        `the canonical block matched ${name}, which is not a request source. The binding requirement ` +
          "or one of the not-insides has been widened away (#1344/#1544).",
      ).toBe(false);
    });
  });

  it("is used by every server-side taint rule that is not narrow by design", () => {
    const offenders = ruleFiles()
      .flatMap(parseRules)
      .filter(
        (r) =>
          r.taint &&
          !r.sources.includes("*request_source") &&
          !takesClientSource(r) &&
          NARROW_BY_DESIGN[r.id] === undefined &&
          PENDING_JUDGMENT[r.id] === undefined,
      )
      .map((r) => `${r.file}:${r.id}`);

    expect(
      offenders,
      "these taint rules hand-roll their own source list. Use `- *request_source`, or add the rule " +
        "to NARROW_BY_DESIGN with the reason it is deliberately narrower. A silently divergent copy " +
        "is exactly the #1221 defect.",
    ).toEqual([]);
  });

  it("gives every client sink rule the shared DOM source block", () => {
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const missing = CLIENT_RULES.filter((id) => !byId.get(id)?.sources.includes("*dom_source"));
    expect(
      missing,
      "these client sink rules hand-roll their own DOM source list. #1223 measured three of them " +
        "blind to location.hash/.search while two siblings in the same file declared both.",
    ).toEqual([]);
  });

  it("keeps the DOM source block carrying the fragment", () => {
    const xss = readFileSync(join(RULES_DIR, "xss.yml"), "utf8");
    const start = xss.indexOf("x-dom-source: &dom_source\n");
    expect(start).toBeGreaterThan(-1);
    const body = xss.slice(start).split(/\n(?=\S)/)[0]!;
    for (const pattern of ["location.hash", "location.search"]) {
      expect(body, `the DOM source block lost ${pattern} — the shape #1223 exists to add`).toContain(pattern);
    }
  });

  // #1708: injection.yml's client-URL-param source is a NARROWING of xss.yml's x-dom-source, not a
  // copy of it, and this is the property that makes it one. xss.yml can afford a receiver-agnostic
  // `$SP.get(...)` / `$RT.query.$K` because its sinks exist only in a browser; injection.yml's
  // original three widened sinks (supabase-js storage / .rpc / .or) run on both sides, so the bare arms fire
  // on every server-side `.get()` and every `.query.` access. MEASURED 2026-08-01, semgrep 1.164.0,
  // over targets/calibration/src/client-url-source: bare arms 5 findings (two at ERROR, i.e. the
  // graded free count), bound arms 1 (the directory's scope control). The four negatives there are
  // the scored gate; this test is the structural one, so a refactor that leaves the fixtures
  // passing for some other reason still fails on the shape itself.
  it("binds the receiver on injection.yml's client URL param source (#1708)", () => {
    const block = anchorBlock("injection.yml", "x-client-url-source: &client_url_source");
    expect(block, "injection.yml no longer declares x-client-url-source").toBeDefined();
    const doc = parse(readFileSync(join(RULES_DIR, "injection.yml"), "utf8")) as Record<string, unknown>;
    const source = doc["x-client-url-source"] as Record<string, unknown>;
    const sourceArms = Array.isArray(source["pattern-either"]) ? source["pattern-either"] : [];
    for (const arm of ["$SP.get(...)", "$RT.query.$K"]) {
      const matchingArms = sourceArms.filter((candidate) => patternStrings(candidate).includes(arm));
      expect(matchingArms, `x-client-url-source must carry exactly one ${arm} arm`).toHaveLength(1);
      expect(
        matchingArms[0],
        `${arm} is unbound in x-client-url-source — a receiver-agnostic arm fires on every ` +
          "server-side Map/Headers/config .get() and on Drizzle's db.query.<table>, reaching the " +
          "ERROR/HIGH graded free count through harvey-sql-injection-rpc",
      ).toHaveProperty("patterns");
      expect(JSON.stringify(matchingArms[0])).toContain("metavariable-regex");
    }
    for (const requestBodyShape of ["formData()", "FormData", "$REQ.formData"]) {
      expect(
        block,
        `x-client-url-source contains ${requestBodyShape}; request.formData()/FormData.get() are ` +
          "the separate request-body source class owned by #1814, not a client URL source",
      ).not.toContain(requestBodyShape);
    }
  });

  it("has no stale exemptions", () => {
    const taintIds = new Set(ruleFiles().flatMap(parseRules).filter((r) => r.taint).map((r) => r.id));
    const stale = [...Object.keys(NARROW_BY_DESIGN), ...Object.keys(PENDING_JUDGMENT), ...CLIENT_RULES].filter(
      (id) => !taintIds.has(id),
    );
    expect(stale, "these rules no longer exist or are no longer taint rules").toEqual([]);
  });

  it("does not leave a resolved rule sitting in PENDING_JUDGMENT", () => {
    const adopted = ruleFiles()
      .flatMap(parseRules)
      .filter((r) => r.sources.includes("*request_source") && PENDING_JUDGMENT[r.id] !== undefined)
      .map((r) => r.id);
    expect(adopted, "these rules now use the canonical block — drop them from PENDING_JUDGMENT").toEqual([]);
  });

  // #1708: every rule that consumes *request_source must have a FINAL in/out judgment for client
  // URL params — silently leaving one out is exactly the "unstated limitation reads as a clean bill
  // of health" failure the rest of this repo's disclosure families exist to prevent. parseRules()
  // obtains this inventory from the YAML parser and resolved alias identities, not a regex census.
  it("judges every request-source rule in or out of class for client URL params (#1708)", () => {
    const requestSourceRuleIds = ruleFiles()
      .flatMap(parseRules)
      .filter((r) => r.taint && r.sources.includes("*request_source"))
      .map((r) => r.id);
    const judged = new Set([
      ...Object.keys(CLIENT_URL_PARAM_IN_CLASS),
      ...Object.keys(CLIENT_URL_PARAM_OUT_OF_CLASS),
    ]);
    const unjudged = [...new Set(requestSourceRuleIds)].filter((id) => !judged.has(id));
    expect(
      unjudged,
      "these request-source rules have no #1708 client-URL-param judgment recorded — add each to " +
        "CLIENT_URL_PARAM_IN_CLASS or CLIENT_URL_PARAM_OUT_OF_CLASS",
    ).toEqual([]);
  });

  it("gives every #1708 IN_CLASS rule a direct client source or its recorded companion", () => {
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const missing = Object.keys(CLIENT_URL_PARAM_IN_CLASS).filter((id) => {
      const companion = CLIENT_URL_PARAM_COMPANIONS[id];
      return !takesClientSource(byId.get(id)) && (companion === undefined || !takesClientSource(byId.get(companion.id)));
    });
    expect(
      missing,
      `these rules are recorded IN_CLASS but neither they nor their recorded companion take ${CLIENT_SOURCE_ANCHORS.join(" or ")} — the judgment and rule inventory have drifted apart`,
    ).toEqual([]);
  });

  it("does not carry a client source block on a request-source rule with no #1708 IN_CLASS judgment", () => {
    // The mirror-image check: a rule quietly gaining a client source without the judgment being
    // recorded, which is exactly as silent a drift as the missing case above.
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const undeclared = Object.keys(CLIENT_URL_PARAM_OUT_OF_CLASS).filter((id) => takesClientSource(byId.get(id)));
    expect(undeclared, `these rules take a client source block (${CLIENT_SOURCE_ANCHORS.join("/")}) but are recorded OUT_OF_CLASS — move them to CLIENT_URL_PARAM_IN_CLASS or drop the pattern`).toEqual([]);
  });

  it("keeps eval's server Critical rule separate from its Medium/review client companion", () => {
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const server = byId.get("harvey-code-injection-eval")!;
    const companionSpec = CLIENT_URL_PARAM_COMPANIONS[server.id]!;
    const companion = byId.get(companionSpec.id)!;

    expect(server.sources).toEqual(["*request_source"]);
    expect({ severity: server.severity, confidence: server.confidence, harveySeverity: server.harveySeverity }).toEqual({
      severity: "ERROR", confidence: "HIGH", harveySeverity: "Critical",
    });
    expect(companion.sources).toEqual(["*client_url_source"]);
    expect({ severity: companion.severity, confidence: companion.confidence, harveySeverity: companion.harveySeverity }).toEqual({
      severity: companionSpec.severity,
      confidence: companionSpec.confidence,
      harveySeverity: companionSpec.harveySeverity,
    });
    expect(companion.sinks, "the client companion must use the exact eval/new Function sink inventory").toEqual(server.sinks);
    expect(companion.sanitizers, "the client companion must preserve the server rule's precision guards").toEqual(server.sanitizers);
  });

  it("limits the CSV client companion to PapaParse and SheetJS while retaining all server families", () => {
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const server = byId.get("harvey-csv-formula-injection")!;
    const companionSpec = CLIENT_URL_PARAM_COMPANIONS[server.id]!;
    const companion = byId.get(companionSpec.id)!;
    const serverPatterns = patternStrings(server.sinks);
    const clientPatterns = patternStrings(companion.sinks);

    expect(server.sources).toEqual(["*request_source"]);
    expect(companion.sources).toEqual(["*client_url_source"]);
    expect({ severity: companion.severity, confidence: companion.confidence, harveySeverity: companion.harveySeverity }).toEqual({
      severity: companionSpec.severity,
      confidence: companionSpec.confidence,
      harveySeverity: companionSpec.harveySeverity,
    });
    for (const pattern of [
      "stringify($X, ...)", "writeToString($X, ...)", "$P.unparse($X, ...)",
      "$P.json_to_sheet($X, ...)", "$P.aoa_to_sheet($X, ...)", "new $P($OPTS).parse($X, ...)",
    ]) {
      expect(serverPatterns, `the request-source CSV rule lost server sink ${pattern}`).toContain(pattern);
    }
    expect(clientPatterns.sort()).toEqual([
      "$P.aoa_to_sheet($X, ...)", "$P.json_to_sheet($X, ...)", "$P.unparse($X, ...)",
    ].sort());
  });

  it("keeps XXE client URL input excluded and dynamic dispatch at its existing review band", () => {
    const byId = new Map(ruleFiles().flatMap(parseRules).map((r) => [r.id, r]));
    const xxe = byId.get("harvey-xxe-parse")!;
    const dispatch = byId.get("harvey-dynamic-dispatch")!;

    expect(xxe.sources).toEqual(["*request_source"]);
    expect(CLIENT_URL_PARAM_OUT_OF_CLASS[xxe.id]).toContain("browser-native DOMParser");
    expect(xxe.message).toContain("Browser-native DOMParser");
    expect(dispatch.sources).toEqual(["*request_source", "*client_url_source"]);
    expect({ severity: dispatch.severity, confidence: dispatch.confidence, harveySeverity: dispatch.harveySeverity }).toEqual({
      severity: "WARNING", confidence: "MEDIUM", harveySeverity: "Medium",
    });
  });

  it("has no stale #1708 client-URL-param judgments", () => {
    const taintIds = new Set(ruleFiles().flatMap(parseRules).filter((r) => r.taint).map((r) => r.id));
    const stale = [
      ...Object.keys(CLIENT_URL_PARAM_IN_CLASS),
      ...Object.keys(CLIENT_URL_PARAM_OUT_OF_CLASS),
    ].filter((id) => !taintIds.has(id));
    expect(stale, "these rules no longer exist or are no longer taint rules — drop their #1708 judgment").toEqual([]);

    const missingCompanions = Object.values(CLIENT_URL_PARAM_COMPANIONS).filter(({ id }) => !taintIds.has(id)).map(({ id }) => id);
    expect(missingCompanions, "these recorded #1708 client companions no longer exist or are no longer taint rules").toEqual([]);
  });
});
