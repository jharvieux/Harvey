// #1573 — the shipping CLI line had no failing direction.
//
// src/acceptance-conservation.ts is proven in depth by its own suite, but everything between `gh`
// and that library — the `--pr` flag parse, the `body,closingIssuesReferences` field list, and
// handing `linkedCloses` to checkAcceptance — was unguarded. MEASURED on this branch before the
// fix: replacing `{ linkedCloses }` with `{ linkedCloses: [] }` in src/cli/validate-acceptance.ts
// left `tsc --noEmit` at exit 0, all 89 tests in src/acceptance-conservation.test.ts passing, and
// `--selftest` at exit 0 — because the self-test hands `linkedCloses` straight to the library and
// never travels the CLI's own wiring. That is the #1407 class: library-level proof, shipping line
// unguarded.
//
// So these drive the REAL CLI as a child process against a stub `gh` on PATH. The stub emulates the
// one behaviour that makes the field list load-bearing: `gh ... --json a,b` returns ONLY the
// requested keys, so dropping `closingIssuesReferences` from the CLI's request makes it vanish here
// exactly as it would against real GitHub.

import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-acceptance.ts");
const REPO = "acme/widgets";

// A stand-in for `gh`, faithful in the two ways this gate depends on: it honours `--json` by
// returning only the requested fields, and it fails with GitHub's own "could not resolve to an
// issue" wording for a fixture that is not there, which is the one stderr the CLI is allowed to
// read as "does not exist".
const FAKE_GH = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const [kind, verb, id] = args;
// Mutations are RECORDED, never emulated: the --act tests assert which side effects the CLI asked
// for, which is exactly the seam where the #1696 divergence lived.
if ((kind === "issue" && ["edit", "comment", "reopen"].includes(verb)) || (kind === "label" && verb === "create")) {
  if (process.env.HARVEY_GH_LOG) fs.appendFileSync(process.env.HARVEY_GH_LOG, JSON.stringify(args) + "\\n");
  process.exit(0);
}
if (verb !== "view" || (kind !== "issue" && kind !== "pr")) {
  console.error("stub gh: unexpected invocation: " + args.join(" "));
  process.exit(1);
}
const file = path.join(process.env.HARVEY_GH_FIXTURES, kind + "-" + id + ".json");
if (!fs.existsSync(file)) {
  console.error("could not resolve to an " + (kind === "pr" ? "pull request" : "issue") + " with the number of " + id);
  process.exit(1);
}
const full = JSON.parse(fs.readFileSync(file, "utf8"));
const jqAt = args.indexOf("--jq");
if (jqAt !== -1) {
  if (args[jqAt + 1] !== '[.labels[].name] | join(",")') {
    console.error("stub gh: unsupported --jq: " + args[jqAt + 1]);
    process.exit(1);
  }
  process.stdout.write((full.labels || []).map((l) => l.name).join(","));
  process.exit(0);
}
const at = args.indexOf("--json");
const fields = at === -1 ? Object.keys(full) : args[at + 1].split(",");
const out = {};
for (const f of fields) if (f in full) out[f] = full[f];
process.stdout.write(JSON.stringify(out));
`;

const ISSUE_700 = {
  number: 700,
  state: "OPEN",
  body: "## Acceptance\n- the sidebar close is checked\n- the field list is load-bearing\n",
  comments: [],
};

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function world(fixtures: Record<string, unknown>): { bin: string; fixtureDir: string } {
  const fixtureDir = mkdtempSync(join(tmpdir(), "harvey-gh-fixtures-"));
  dirs.push(fixtureDir);
  for (const [name, value] of Object.entries(fixtures)) {
    writeFileSync(join(fixtureDir, `${name}.json`), JSON.stringify(value));
  }
  const bin = mkdtempSync(join(tmpdir(), "harvey-gh-bin-"));
  dirs.push(bin);
  const stub = join(bin, "gh");
  writeFileSync(stub, FAKE_GH);
  chmodSync(stub, 0o755);
  return { bin, fixtureDir };
}

function cli(args: string[], fixtures: Record<string, unknown>): { code: number; out: string } {
  const { bin, fixtureDir } = world(fixtures);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir };
  try {
    const out = execFileSync("node_modules/.bin/tsx", [CLI, ...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, out };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { code: err.status, out: `${err.stdout}${err.stderr}` };
  }
}

describe("validate-acceptance CLI — the Development-sidebar close reaches the gate (#1573)", () => {
  // THE FAILING DIRECTION for the shipping line. The PR body carries no closing keyword, so the
  // body parser finds nothing; the ONLY thing that puts #700 on trial is `closingIssuesReferences`
  // travelling from the `gh pr view` field list into checkAcceptance's `linkedCloses`. Revert
  // either half and this exits 0 with a green no-op instead of 1.
  it("fails a PR that closes an issue through the sidebar with no keyword in its body", () => {
    const r = cli(["--pr", "900", "--repo", REPO], {
      "pr-900": { body: "Refactors the seeder. refs #700\n", closingIssuesReferences: [{ number: 700 }] },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain("1 closing reference(s) — #700");
    expect(r.out).toContain("700.1");
    expect(r.out).toContain("UNMAPPED");
  });

  // NEGATIVE CONTROL for the test above: the same body, the same issue, and the ONLY difference is
  // that GitHub records no close. It must go green — otherwise the assertion above would hold for a
  // PR whose body merely mentions #700, and would pass with the wiring reverted.
  it("green no-ops on the same body when GitHub records no closing reference", () => {
    const r = cli(["--pr", "901", "--repo", REPO], {
      "pr-901": { body: "Refactors the seeder. refs #700\n", closingIssuesReferences: [] },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("NO-OP");
  });

  it("passes a sidebar close whose dispositions are recorded, so the check is not just 'sidebar = fail'", () => {
    const r = cli(["--pr", "902", "--repo", REPO], {
      "pr-902": {
        body: [
          "Refactors the seeder. refs #700",
          "",
          "ACCEPTANCE #700.1 met: src/cli/validate-acceptance.test.ts drives the real CLI",
          "ACCEPTANCE #700.2 met: the stub `gh` honours `--json`, so a dropped field vanishes",
        ].join("\n"),
        closingIssuesReferences: [{ number: 700 }],
      },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("every acceptance bullet");
  });

  // The body-keyword path through the same CLI, so a regression that broke `--pr` parsing outright
  // could not hide behind the sidebar cases above.
  it("still fails a PR that closes by keyword with no disposition", () => {
    const r = cli(["--pr", "903", "--repo", REPO], {
      "pr-903": { body: "Closes #700\n", closingIssuesReferences: [{ number: 700 }] },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain("UNMAPPED");
  });

  it("exits 2 — could not RUN, not failed — when the PR itself cannot be read", () => {
    const r = cli(["--pr", "999", "--repo", REPO], { "issue-700": ISSUE_700 });
    expect(r.code).toBe(2);
  });
});

// #1573 criterion 3. The row's first clause used to read "reads the text supplied and nothing else",
// which is false on its own — two sentences later the same row correctly says issue comments WERE
// read. A skimmer keeps the first clause.
describe("validate-acceptance --body-file discloses exactly what it did not consult (#1573)", () => {
  it("names the sidebar as the unchecked half without claiming it read nothing else", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-body-"));
    dirs.push(dir);
    const bodyFile = join(dir, "pr-body.md");
    writeFileSync(bodyFile, "Refactors the seeder. refs #700\n");
    const { bin, fixtureDir } = world({ "issue-700": ISSUE_700 });
    const out = execFileSync("node_modules/.bin/tsx", [CLI, "--body-file", bodyFile, "--repo", REPO], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir },
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(out).toContain("NOT ASSESSED");
    expect(out).toContain("closingIssuesReferences");
    // The defect: no clause may be false read alone.
    expect(out).not.toContain("and nothing else");
    // And the row still has to say what it DID read, or the fix trades one half-truth for another.
    expect(out).toContain("Issue comments and every LINKED PR body WERE read");
  });
});

// #1581. The library proves the venue set is collected in one place; these prove the CLI actually
// FETCHES it. The wiring under test is the `closedByPullRequestsReferences` field on the issue
// request, the `gh pr view` that turns each reference into a body, and the `selfPr` exclusion —
// none of which the library suite travels. The stub honours `--json`, so dropping the field from
// the CLI's request makes the second PR vanish here exactly as it would against real GitHub.
describe("validate-acceptance CLI — an issue closed by TWO PRs is one venue set (#1581)", () => {
  const dispositions = [
    "ACCEPTANCE #700.1 met: src/cli/validate-acceptance.ts fetches every linked PR body",
    "ACCEPTANCE #700.2 met: src/cli/validate-acceptance.test.ts drives the real CLI",
  ];
  const linked = (...numbers: number[]): Record<string, unknown> => ({
    ...ISSUE_700,
    closedByPullRequestsReferences: numbers.map((number) => ({ number })),
  });

  it("fails a PR whose criteria the OTHER linked closing PR also dispositions", () => {
    const r = cli(["--pr", "910", "--repo", REPO], {
      "pr-910": { body: `Closes #700\n\n${dispositions.join("\n")}\n`, closingIssuesReferences: [{ number: 700 }] },
      "pr-911": { body: `Closes #700\n\n${dispositions.join("\n")}\n` },
      "issue-700": linked(910, 911),
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain("mapped 2 times");
    expect(r.out).toContain("linked PR #911");
  });

  // NEGATIVE CONTROL for the case above: two linked PRs is not itself the failure — splitting the
  // criteria between them is the normal, passing shape.
  it("passes two linked PRs that disposition one criterion each", () => {
    const r = cli(["--pr", "912", "--repo", REPO], {
      "pr-912": { body: `Closes #700\n\n${dispositions[0]}\n`, closingIssuesReferences: [{ number: 700 }] },
      "pr-913": { body: `Closes #700\n\n${dispositions[1]}\n` },
      "issue-700": linked(912, 913),
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("every acceptance bullet");
  });

  // THE selfPr EXCLUSION, as a shipping line with a failing direction: this PR is one of its own
  // issue's linked PRs, so without the exclusion its every criterion reads as mapped twice and a
  // correct PR is rejected.
  it("does not read the PR under test as its own linked venue", () => {
    const r = cli(["--pr", "914", "--repo", REPO], {
      "pr-914": { body: `Closes #700\n\n${dispositions.join("\n")}\n`, closingIssuesReferences: [{ number: 700 }] },
      "issue-700": linked(914),
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("every acceptance bullet");
  });

  // The close path over the same fixtures, so the two CLI paths are watched agreeing rather than
  // each being watched alone. This is the arrangement that broke: PR green, close red.
  it("--closed-issue reaches the same verdict as --pr on the same state", () => {
    const fixtures = {
      "pr-910": { body: `Closes #700\n\n${dispositions.join("\n")}\n`, closingIssuesReferences: [{ number: 700 }] },
      "pr-911": { body: `Closes #700\n\n${dispositions.join("\n")}\n` },
      "issue-700": { ...linked(910, 911), author: { login: "jharvieux", is_bot: false } },
    };
    expect(cli(["--closed-issue", "700", "--repo", REPO], fixtures).code).toBe(1);
    expect(cli(["--pr", "910", "--repo", REPO], fixtures).code).toBe(1);
  });
});

// #1696. The gate used to reach two terminal states for one class of error: a first defective close
// was re-opened, a repeat one stood CLOSED behind an `acceptance-unaccounted` label — which is how
// #1285's em-dash close ended silent while #1436's empty one went back in the queue the same hour.
// These drive the real CLI with --act against the stub `gh`, which RECORDS every mutation it is
// asked for: the assertion surface is exactly the side-effect list where the divergence lived.
describe("validate-acceptance --act — ONE terminal state for a failed close (#1696)", () => {
  const author = { login: "jharvieux", is_bot: false };
  const asked = (log: string, ...head: string[]): boolean =>
    log.split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]).some((a) => head.every((h, i) => a[i] === h));

  function act(fixtures: Record<string, unknown>): { code: number; log: string } {
    const { bin, fixtureDir } = world(fixtures);
    const logFile = join(fixtureDir, "mutations.log");
    writeFileSync(logFile, "");
    try {
      execFileSync("node_modules/.bin/tsx", [CLI, "--closed-issue", "700", "--repo", REPO, "--act"], {
        cwd: REPO_ROOT,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir, HARVEY_GH_LOG: logFile },
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { code: 0, log: readFileSync(logFile, "utf8") };
    } catch (e) {
      return { code: (e as { status: number }).status, log: readFileSync(logFile, "utf8") };
    }
  }

  // THE BRANCH THAT CHANGED: label already present, bookkeeping still defective. Under the old
  // "re-open once" rule this was commented and re-labelled but STOOD CLOSED — the silent outcome.
  it("re-opens a repeat failure — a near-miss `met —` close with the label already present", () => {
    const r = act({
      "issue-700": {
        ...ISSUE_700,
        author,
        labels: [{ name: "acceptance-unaccounted" }],
        comments: [
          { body: "ACCEPTANCE #700.1 met — src/acceptance-conservation.ts now checks it" },
          { body: "ACCEPTANCE #700.2 met: src/acceptance-conservation.test.ts covers it" },
        ],
      },
    });
    expect(r.code).toBe(1);
    expect(asked(r.log, "issue", "reopen", "700")).toBe(true);
    expect(asked(r.log, "issue", "comment", "700")).toBe(true);
  });

  it("re-opens a first-time failure — a bare click with no ACCEPTANCE lines and no label yet", () => {
    const r = act({ "issue-700": { ...ISSUE_700, author, labels: [] } });
    expect(r.code).toBe(1);
    expect(asked(r.log, "issue", "reopen", "700")).toBe(true);
    expect(asked(r.log, "issue", "edit", "700", "--repo", REPO, "--add-label")).toBe(true);
  });

  // The control direction: a well-formed close is not touched, and a stale label is removed rather
  // than left standing as a false statement about the issue.
  it("does not re-open a well-formed close, and removes a stale label", () => {
    const r = act({
      "issue-700": {
        ...ISSUE_700,
        author,
        labels: [{ name: "acceptance-unaccounted" }],
        comments: [
          { body: "ACCEPTANCE #700.1 met: src/acceptance-conservation.ts now checks it" },
          { body: "ACCEPTANCE #700.2 met: src/acceptance-conservation.test.ts covers it" },
        ],
      },
    });
    expect(r.code).toBe(0);
    expect(asked(r.log, "issue", "reopen")).toBe(false);
    expect(asked(r.log, "issue", "comment")).toBe(false);
    expect(asked(r.log, "issue", "edit", "700", "--repo", REPO, "--remove-label")).toBe(true);
  });
});
