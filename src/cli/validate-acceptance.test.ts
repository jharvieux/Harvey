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

import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkClosedIssue, closeFailureComment, SELFTEST_WORLD } from "../acceptance-conservation.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-acceptance.ts");
const REPO = "acme/widgets";

// A stand-in for `gh`, faithful in the two ways this gate depends on: it honours `--json` by
// returning only the requested fields, and it fails with GitHub's own "could not resolve to an
// issue" wording for a fixture that is not there, which is the one stderr the CLI is allowed to
// read as "does not exist".
const FAKE_GH = `#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const [kind, verb, id] = args;
// Mutations are RECORDED, never emulated: the --act tests assert which side effects the CLI asked
// for, which is exactly the seam where the #1696 divergence lived.
if ((kind === "issue" && ["edit", "comment", "reopen"].includes(verb)) || (kind === "label" && verb === "create")) {
  if (process.env.HARVEY_GH_LOG) fs.appendFileSync(process.env.HARVEY_GH_LOG, JSON.stringify(args) + "\\n");
  if (kind === "issue" && verb === "comment" && process.env.HARVEY_GH_INPUT_LOG) {
    fs.writeFileSync(process.env.HARVEY_GH_INPUT_LOG, JSON.stringify({ argv: args, input: fs.readFileSync(0, "utf8") }));
  }
  if (kind === "issue" && verb === "edit" && args.includes("--add-label") && process.env.HARVEY_GH_BREAK_COMMENT) fs.chmodSync(process.argv[1], 0o644);
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

const ISSUE_2189_BODY = `Independent acceptance review of wave 4 at \`e8e401a38b2becfa34d54ac06e885b97a363f1a9\` found a remaining command receipt outcome distinction in \`src/probe-exec.ts\`.

A real child emitting 2 MiB exceeded \`spawnSync\`'s output buffer. The child did start, but the receipt classified \`ENOBUFS\` as \`spawn-failed\`. Only 1,114,112 captured bytes were retained, without an explicit truncation flag. The receipt remained non-success, so this does not establish false acceptance. It does make the command history and output-digest coverage ambiguous.

A related malformed input control found that the receipt parser accepts an outcome combining \`state: timed-out\` and \`exitCode: 0\`; the success predicate correctly rejects it. The parser should enforce coherent outcome fields.

Acceptance:

- Distinguish failures before process start from a started process interrupted by output limits, retaining observed exit/signal/error information without inventing success.
- Explicitly record whether captured stdout/stderr are complete or truncated, and state that their hashes cover captured bytes when completeness is unknown or false.
- Reject contradictory outcome field combinations at the receipt parser boundary.
- Exercise a real output-overflow child and malformed receipt controls, with failing directions; keep all affected receipts non-success and preserve secret redaction.

This bounded follow-up comes from the #2139 same-class census. Existing broader journey and install-execution issues do not own this concrete receipt contract defect. No timeout, buffer, or acceptance threshold should be raised merely to avoid the control.
`;

const ISSUE_2209_BODY = `Independent acceptance of #2138 at \`02e2969143a3e4f8f7f9d196d38dae81f58cd565\` confirms correct production behavior: installed pg_net/http are capability inventory (Info/review), not proof of exploitable outbound access. Actual scanner → assembly → HTML preserves that distinction.

The three existing \`src/scan/supabase-config.test.ts:245\` extension controls remain green when production severity is physically changed from Info to High (baseline/mutation/restored exits 0/0/0). The separate independent shipping-consumer control detects the same mutation (0/1/0). Retain that control in the repository so future regression protection does not depend on a temporary acceptance script.

Acceptance:
- Exercise installed and absent pg_net/http through the shipping scanner, canonical assembly, and rendered report using an owned API fixture.
- Assert installed capability remains Info/review with the provenance limitation and no attacker-controlled URL/exploit claim; absent extensions emit no capability row.
- Physically change the production capability severity to High or remove the limitation: the relevant consumer assertion must fail, then pass after restoration.
- Preserve existing extension controls and run the required local gate.

This is a regression-coverage follow-up, not an observed current exposure-classification defect. Deduplication found only the parent #2138, whose full authorization behavior and six acceptance criteria have independent passing evidence.

Evidence: \`/tmp/harvey-authorization-final-acceptance.json\`; source controls and actual results in \`/private/tmp/harvey-authorization-independent-inverses-n9tyw84m/acceptance-evidence/extension-consumer.ts\`, \`extension-consumer-inverse.json\`, and \`extra-inverses.json\`. The immutable revision and observed exit sequences are retained here because those temporary artifacts are local.
`;

const PLAIN_ACCEPTANCE_ISSUES = [
  { issue: 2189, pr: 940, body: ISSUE_2189_BODY },
  { issue: 2209, pr: 941, body: ISSUE_2209_BODY },
] as const;

function issueFixture(number: number, body: string, linkedPrs: number[] = []): Record<string, unknown> {
  return {
    number,
    state: "OPEN",
    body,
    comments: [],
    closedByPullRequestsReferences: linkedPrs.map((linked) => ({ number: linked })),
  };
}

function disposition(issue: number, count = 4): string {
  return Array.from({ length: count }, (_, index) =>
    `ACCEPTANCE #${issue}.${index + 1} met: src/cli/validate-acceptance.test.ts exercises criterion ${index + 1}`,
  ).join("\n");
}

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

function run(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; out: string; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, ["--import", join(REPO_ROOT, "node_modules/tsx/dist/loader.mjs"), CLI, ...args], {
      cwd: REPO_ROOT,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ code: code ?? 1, out: `${stdout}${stderr}`, stdout, stderr }));
  });
}

function cli(args: string[], fixtures: Record<string, unknown>): Promise<{ code: number; out: string }> {
  const { bin, fixtureDir } = world(fixtures);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir };
  return run(args, env);
}

describe("validate-acceptance CLI — the Development-sidebar close reaches the gate (#1573)", () => {
  // THE FAILING DIRECTION for the shipping line. The PR body carries no closing keyword, so the
  // body parser finds nothing; the ONLY thing that puts #700 on trial is `closingIssuesReferences`
  // travelling from the `gh pr view` field list into checkAcceptance's `linkedCloses`. Revert
  // either half and this exits 0 with a green no-op instead of 1.
  it("fails a PR that closes an issue through the sidebar with no keyword in its body", async () => {
    const r = await cli(["--pr", "900", "--repo", REPO], {
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
  it("green no-ops on the same body when GitHub records no closing reference", async () => {
    const r = await cli(["--pr", "901", "--repo", REPO], {
      "pr-901": { body: "Refactors the seeder. refs #700\n", closingIssuesReferences: [] },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("NO-OP");
  });

  it("passes a sidebar close whose dispositions are recorded, so the check is not just 'sidebar = fail'", async () => {
    const r = await cli(["--pr", "902", "--repo", REPO], {
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
  it("still fails a PR that closes by keyword with no disposition", async () => {
    const r = await cli(["--pr", "903", "--repo", REPO], {
      "pr-903": { body: "Closes #700\n", closingIssuesReferences: [{ number: 700 }] },
      "issue-700": ISSUE_700,
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain("UNMAPPED");
  });

  it("exits 2 — could not RUN, not failed — when the PR itself cannot be read", async () => {
    const r = await cli(["--pr", "999", "--repo", REPO], { "issue-700": ISSUE_700 });
    expect(r.code).toBe(2);
  });
});

// #1573 criterion 3. The row's first clause used to read "reads the text supplied and nothing else",
// which is false on its own — two sentences later the same row correctly says issue comments WERE
// read. A skimmer keeps the first clause.
describe("validate-acceptance --body-file discloses exactly what it did not consult (#1573)", () => {
  it("names the sidebar as the unchecked half without claiming it read nothing else", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-body-"));
    dirs.push(dir);
    const bodyFile = join(dir, "pr-body.md");
    writeFileSync(bodyFile, "Refactors the seeder. refs #700\n");
    const { bin, fixtureDir } = world({ "issue-700": ISSUE_700 });
    const result = await run(["--body-file", bodyFile, "--repo", REPO], { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir });
    expect(result.code).toBe(0);
    expect(result.out).toContain("NOT ASSESSED");
    expect(result.out).toContain("closingIssuesReferences");
    // The defect: no clause may be false read alone.
    expect(result.out).not.toContain("and nothing else");
    // And the row still has to say what it DID read, or the fix trades one half-truth for another.
    expect(result.out).toContain("Issue comments and every LINKED PR body WERE read");
  });
});

describe("validate-acceptance CLI — standalone Acceptance: labels are criteria-bearing (#2214)", () => {
  for (const sample of PLAIN_ACCEPTANCE_ISSUES) {
    it(`rejects no-stated-criteria for the exact #${sample.issue} body`, async () => {
      const r = await cli(["--pr", String(sample.pr), "--repo", REPO], {
        [`pr-${sample.pr}`]: {
          body: `Closes #${sample.issue}\n\nACCEPTANCE #${sample.issue} no-stated-criteria: the production behavior described by the issue body`,
          closingIssuesReferences: [{ number: sample.issue }],
        },
        [`issue-${sample.issue}`]: issueFixture(sample.issue, sample.body),
      });
      expect(r.code).toBe(1);
      expect(r.out).toContain(`declares \`no-stated-criteria\` but the issue states 4`);
      expect(r.out).toContain(`0/4 criteria dispositioned`);
    });

    it(`passes complete positional mappings for the exact #${sample.issue} body`, async () => {
      const r = await cli(["--pr", String(sample.pr), "--repo", REPO], {
        [`pr-${sample.pr}`]: {
          body: `Closes #${sample.issue}\n\n${disposition(sample.issue)}`,
          closingIssuesReferences: [{ number: sample.issue }],
        },
        [`issue-${sample.issue}`]: issueFixture(sample.issue, sample.body),
      });
      expect(r.code).toBe(0);
      expect(r.out).toContain(`4/4 criteria dispositioned`);
      expect(r.out).toContain(`every acceptance bullet of every issue this PR closes is mapped`);
    });

    it(`treats the Markdown heading equivalent of #${sample.issue} identically`, async () => {
      const markdownBody = sample.body.replace(/^Acceptance:$/m, "## Acceptance");
      const r = await cli(["--pr", String(sample.pr), "--repo", REPO], {
        [`pr-${sample.pr}`]: {
          body: `Closes #${sample.issue}\n\n${disposition(sample.issue)}`,
          closingIssuesReferences: [{ number: sample.issue }],
        },
        [`issue-${sample.issue}`]: issueFixture(sample.issue, markdownBody),
      });
      expect(r.code).toBe(0);
      expect(r.out).toContain(`4/4 criteria dispositioned`);
    });
  }

  it("fails when one bullet from a plain Acceptance: section is unmapped", async () => {
    const r = await cli(["--pr", "942", "--repo", REPO], {
      "pr-942": {
        body: `Closes #2189\n\n${disposition(2189, 3)}`,
        closingIssuesReferences: [{ number: 2189 }],
      },
      "issue-2189": issueFixture(2189, ISSUE_2189_BODY),
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain("2189.4");
    expect(r.out).toContain("UNMAPPED");
  });

  it("preserves linked-venue conservation for a plain Acceptance: section", async () => {
    const r = await cli(["--pr", "943", "--repo", REPO], {
      "pr-943": {
        body: `Closes #2189\n\n${disposition(2189, 2)}`,
        closingIssuesReferences: [{ number: 2189 }],
      },
      "pr-944": {
        body: [
          "ACCEPTANCE #2189.3 met: src/cli/validate-acceptance.test.ts exercises linked criterion 3",
          "ACCEPTANCE #2189.4 met: src/cli/validate-acceptance.test.ts exercises linked criterion 4",
        ].join("\n"),
      },
      "issue-2189": issueFixture(2189, ISSUE_2189_BODY, [944]),
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("2 venues supplied disposition lines");
    expect(r.out).toContain("4/4 criteria dispositioned");
  });

  it("keeps the genuine no-criteria contract: declaration passes and omission fails", async () => {
    const issue = issueFixture(22140, "Please make the scanner faster.\n");
    const declared = await cli(["--pr", "945", "--repo", REPO], {
      "pr-945": {
        body: "Closes #22140\n\nACCEPTANCE #22140 no-stated-criteria: the scanner must complete its documented verification",
        closingIssuesReferences: [{ number: 22140 }],
      },
      "issue-22140": issue,
    });
    expect(declared.code).toBe(0);
    expect(declared.out).toContain("0/0 criteria dispositioned");

    const omitted = await cli(["--pr", "946", "--repo", REPO], {
      "pr-946": { body: "Closes #22140\n", closingIssuesReferences: [{ number: 22140 }] },
      "issue-22140": issue,
    });
    expect(omitted.code).toBe(1);
    expect(omitted.out).toContain("states no acceptance criteria");
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

  it("fails a PR whose criteria the OTHER linked closing PR also dispositions", async () => {
    const r = await cli(["--pr", "910", "--repo", REPO], {
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
  it("passes two linked PRs that disposition one criterion each", async () => {
    const r = await cli(["--pr", "912", "--repo", REPO], {
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
  it("does not read the PR under test as its own linked venue", async () => {
    const r = await cli(["--pr", "914", "--repo", REPO], {
      "pr-914": { body: `Closes #700\n\n${dispositions.join("\n")}\n`, closingIssuesReferences: [{ number: 700 }] },
      "issue-700": linked(914),
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain("every acceptance bullet");
  });

  // The close path over the same fixtures, so the two CLI paths are watched agreeing rather than
  // each being watched alone. This is the arrangement that broke: PR green, close red.
  it("--closed-issue reaches the same verdict as --pr on the same state", async () => {
    const fixtures = {
      "pr-910": { body: `Closes #700\n\n${dispositions.join("\n")}\n`, closingIssuesReferences: [{ number: 700 }] },
      "pr-911": { body: `Closes #700\n\n${dispositions.join("\n")}\n` },
      "issue-700": { ...linked(910, 911), author: { login: "jharvieux", is_bot: false } },
    };
    expect((await cli(["--closed-issue", "700", "--repo", REPO], fixtures)).code).toBe(1);
    expect((await cli(["--pr", "910", "--repo", REPO], fixtures)).code).toBe(1);
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

  async function act(fixtures: Record<string, unknown>): Promise<{ code: number; log: string }> {
    const { bin, fixtureDir } = world(fixtures);
    const logFile = join(fixtureDir, "mutations.log");
    writeFileSync(logFile, "");
    const result = await run(["--closed-issue", "700", "--repo", REPO, "--act"], {
      ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir, HARVEY_GH_LOG: logFile,
    });
    return { code: result.code, log: readFileSync(logFile, "utf8") };
  }

  // THE BRANCH THAT CHANGED: label already present, bookkeeping still defective. Under the old
  // "re-open once" rule this was commented and re-labelled but STOOD CLOSED — the silent outcome.
  it("re-opens a repeat failure — a near-miss `met —` close with the label already present", async () => {
    const r = await act({
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

  it("re-opens a first-time failure — a bare click with no ACCEPTANCE lines and no label yet", async () => {
    const r = await act({ "issue-700": { ...ISSUE_700, author, labels: [] } });
    expect(r.code).toBe(1);
    expect(asked(r.log, "issue", "reopen", "700")).toBe(true);
    expect(asked(r.log, "issue", "edit", "700", "--repo", REPO, "--add-label")).toBe(true);
  });

  // The control direction: a well-formed close is not touched, and a stale label is removed rather
  // than left standing as a false statement about the issue.
  it("does not re-open a well-formed close, and removes a stale label", async () => {
    const r = await act({
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

describe("validate-acceptance comment argv boundary (#1778)", () => {
  const canary = "harvey-acceptance-comment-canary-1778";
  const failedIssue = {
    ...ISSUE_700,
    body: `## Acceptance\n- credential ${canary} with 'quotes', "double quotes" and \\backslash\n`,
    state: "CLOSED", author: { login: "fixture-reviewer", is_bot: false },
    labels: [{ name: "acceptance-unaccounted" }],
  };

  it("delivers the full failed-close comment on stdin while keeping external criterion prose out of gh argv", async () => {
    const { bin, fixtureDir } = world({ "issue-700": failedIssue });
    const inputLog = join(fixtureDir, "comment.json");
    const log = join(fixtureDir, "mutations.log");
    const result = await run(["--closed-issue", "700", "--repo", REPO, "--act"], {
      ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_GH_FIXTURES: fixtureDir,
      HARVEY_GH_INPUT_LOG: inputLog, HARVEY_GH_LOG: log,
    });
    expect(result.code).toBe(1);
    const comment = JSON.parse(readFileSync(inputLog, "utf8")) as { argv: string[]; input: string };
    expect(comment.argv).toEqual(["issue", "comment", "700", "--repo", REPO, "--body-file", "-"]);
    const expected = closeFailureComment(checkClosedIssue({ issue: 700, authorIsBot: false }, () => ({ ...failedIssue, state: "CLOSED" }), REPO, SELFTEST_WORLD));
    expect(comment.input).toBe(expected);
    expect(comment.input).toContain(`credential ${canary} with 'quotes', "double quotes" and \\backslash`);
    expect(comment.input).toContain("UNMAPPED");
    expect(comment.input).toContain("\n");
    expect(readFileSync(log, "utf8")).not.toContain(canary);
    expect(readFileSync(log, "utf8")).toContain('["issue","reopen","700"');
  });

  it("keeps a comment spawn failure diagnostic payload-free without mistaking it for an acceptance verdict", async () => {
    const { bin, fixtureDir } = world({ "issue-700": failedIssue });
    const result = await run(["--closed-issue", "700", "--repo", REPO, "--act"], {
      // No fallback executable is available when the fixture removes its own execute bit.
      ...process.env, PATH: bin, HARVEY_GH_FIXTURES: fixtureDir,
      HARVEY_GH_BREAK_COMMENT: "1",
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("could not be run");
    expect(result.stderr).toContain("EACCES");
    expect(result.stderr).not.toContain(canary);
    // The existing report intentionally prints criteria on stdout; this repair does not promise
    // general output redaction, only that spawn-error diagnostics do not repeat opaque payloads.
    expect(result.stdout).toContain(canary);
  });
});
