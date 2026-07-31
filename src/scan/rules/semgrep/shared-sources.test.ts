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

interface Rule {
  file: string;
  id: string;
  taint: boolean;
  sources: string;
}

function parseRules(file: string): Rule[] {
  const text = readFileSync(join(RULES_DIR, file), "utf8");
  const chunks = text.split(/^ {2}- id: /m).slice(1);
  return chunks.map((chunk) => {
    const id = chunk.split("\n")[0]!.trim();
    const sourcesMatch = /^ {4}pattern-sources:\n((?: {6}.*\n|\n)*)/m.exec(chunk);
    return { file, id, taint: /^ {4}mode: taint$/m.test(chunk), sources: sourcesMatch?.[1] ?? "" };
  });
}

function ruleFiles(): string[] {
  return readNamesSafe(RULES_DIR).filter((f) => f.endsWith(".yml"));
}

// The anchor definition block, from its key to the first line at column 0 that follows it.
function anchorBlock(file: string): string | undefined {
  const text = readFileSync(join(RULES_DIR, file), "utf8");
  const start = text.indexOf("x-request-source: &request_source\n");
  if (start === -1) return undefined;
  const rest = text.slice(start);
  const end = /\n(?=\S)/.exec(rest.slice("x-request-source: &request_source\n".length));
  const block = end === null ? rest : rest.slice(0, "x-request-source: &request_source\n".length + end.index);
  return block.trimEnd();
}

describe("canonical request-taint source block (#1221)", () => {
  it("is byte-identical in every file that declares it", () => {
    const declared = ruleFiles()
      .map((f) => [f, anchorBlock(f)] as const)
      .filter((pair): pair is readonly [string, string] => pair[1] !== undefined);

    expect(declared.length).toBeGreaterThan(1);
    const [firstFile, canonical] = declared[0]!;
    for (const [file, block] of declared.slice(1)) {
      expect(block, `${file}'s copy of the canonical source block has drifted from ${firstFile}'s`).toBe(canonical);
    }
  });

  it("carries the App Router shapes the drift had lost", () => {
    const canonical = anchorBlock("base.yml");
    expect(canonical).toBeDefined();
    for (const pattern of ["await $REQ.json()", "$U.searchParams.get(...)", "$U.searchParams"]) {
      expect(canonical, `the canonical block lost ${pattern} — the shape #1221 exists to add`).toContain(pattern);
    }
    // A bare `$SP.get(...)` was MEASURED to fire on Map/Headers/config/FormData `.get()` even
    // behind ssrf-fetch's http-client guard. It must never re-enter the shared block.
    expect(canonical).not.toContain("- pattern: $SP.get(...)");
  });

  it("carries the Server Component request props, guarded by the not-inside that makes them safe", () => {
    const canonical = anchorBlock("base.yml");
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
    const canonical = anchorBlock("base.yml")!;
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
          !r.sources.includes("*dom_source") &&
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
});
