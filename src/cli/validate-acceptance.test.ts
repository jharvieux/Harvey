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
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
    expect(out).toContain("Issue comments WERE read");
  });
});
