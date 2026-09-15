// Execute the shipped selector, then the shipped validator in physical Git trees. A mocked
// pathExists would erase the old-checkout defect this regression test is meant to preserve.
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parse } from "yaml";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = join(ROOT, ".github/workflows/acceptance-close.yml");
const REPO = "acme/widgets";
const OLD = "1".repeat(40);
const MERGE = "2".repeat(40);
const TIP = "3".repeat(40);
const SOURCE = "4".repeat(40);
const DISPOSITION = "ACCEPTANCE #700.1 met: `src/landed-evidence.ts` records the landed behavior";

interface Step {
  name?: string;
  id?: string;
  uses?: string;
  if?: string;
  with?: Record<string, unknown>;
  env?: Record<string, string>;
  run?: string;
}
interface Workflow {
  on: { issues: { types: string[] }; workflow_dispatch: { inputs: Record<string, unknown> } };
  jobs: { "acceptance-close": { permissions: Record<string, string>; steps: Step[] } };
}
function workflow(): Workflow {
  return parse(readFileSync(WORKFLOW, "utf8")) as Workflow;
}

function merged(number = 900, oid = MERGE) {
  return { number, merged: true, baseRefName: "main", repository: { nameWithOwner: REPO }, mergeCommit: { oid } };
}
type Link = ReturnType<typeof merged>;
type Comparison = { status: string; base_commit: { sha: string }; merge_base_commit: { sha: string } };
interface SelectionOptions {
  event?: string;
  eventSha?: string;
  sourceSha?: string;
  inputIssue?: string;
  drill?: boolean | string;
  tip?: string;
  pages?: Link[][];
  response?: (value: Record<string, unknown>, page: number) => unknown;
  compare?: (base: string, head: string) => Comparison;
}

async function select(options: SelectionOptions = {}) {
  const step = workflow().jobs["acceptance-close"].steps.find((s) => s.id === "evidence-revision");
  expect(step?.env?.GH_TOKEN).toBe("${{ github.token }}");
  expect(step?.uses).toBeUndefined();
  const inline = step?.run?.match(/^node <<'NODE'\n([\s\S]*)\nNODE\s*$/)?.[1];
  expect(inline).toBeDefined();
  const outputs: Record<string, string> = {};
  const queries: { query: string; variables: Record<string, unknown> }[] = [];
  const comparisons: string[] = [];
  const logs: string[] = [];
  let receipt: Record<string, unknown> | undefined;
  let summaryWrites = 0;
  const pages = options.pages ?? [[merged()]];
  const api = (command: string, args: string[], settings: { input?: string }) => {
    expect(command).toBe("gh");
    if (args[1] === "graphql") {
      expect(args).toEqual(["api", "graphql", "--input", "-"]);
      const { query, variables } = JSON.parse(settings.input!) as { query: string; variables: Record<string, unknown> };
      expect(variables.owner).toBe("acme");
      expect(variables.repo).toBe("widgets");
      const page = queries.length;
      queries.push({ query, variables });
      const value = {
        repository: {
          nameWithOwner: REPO,
          defaultBranchRef: { name: "main", target: { __typename: "Commit", oid: options.tip ?? TIP } },
          ...(!variables.drill ? { issue: {
            number: 700,
            closedByPullRequestsReferences: {
              nodes: pages[page] ?? [],
              pageInfo: { hasNextPage: page < pages.length - 1, endCursor: `page-${page}` },
            },
          } } : {}),
        },
      };
      return JSON.stringify({ data: options.response ? options.response(value, page) : value });
    }
    expect(args[0]).toBe("api");
    expect(args).toHaveLength(2);
    const prefix = `repos/${REPO}/compare/`;
    expect(args[1]?.startsWith(prefix)).toBe(true);
    const basehead = args[1]!.slice(prefix.length);
    comparisons.push(basehead);
    const [base, head] = basehead.split("...") as [string, string];
    return JSON.stringify(options.compare?.(base, head) ?? { status: base === head ? "identical" : "ahead", base_commit: { sha: base }, merge_base_commit: { sha: base } });
  };
  runInNewContext(inline!, {
    require: (module: string) => {
      if (module === "node:child_process") return { execFileSync: api };
      expect(module).toBe("node:fs");
      return {
        readFileSync: (path: string) => {
          expect(path).toBe("event.json");
          return JSON.stringify({ issue: { number: 700 }, inputs: { issue: options.inputIssue ?? "700", liveness_drill: options.drill ?? "false" } });
        },
        appendFileSync: (path: string, value: string) => {
          if (path === "summary.md") {
            summaryWrites++;
            receipt = JSON.parse(value.split("```json\n")[1]!.split("\n```")[0]!) as Record<string, unknown>;
          } else {
            expect(path).toBe("outputs.txt");
            for (const line of value.trimEnd().split("\n")) {
              const [key, output] = line.split("=") as [string, string];
              outputs[key] = output;
            }
          }
        },
      };
    },
    console: { log: (value: string) => logs.push(value) },
    process: { env: { GITHUB_WORKFLOW_SHA: options.sourceSha ?? SOURCE, GITHUB_SHA: options.eventSha ?? OLD,
      GITHUB_EVENT_NAME: options.event ?? "issues", GITHUB_REPOSITORY: REPO,
      GITHUB_EVENT_PATH: "event.json", GITHUB_STEP_SUMMARY: "summary.md", GITHUB_OUTPUT: "outputs.txt" } },
  });
  return { outputs, queries, comparisons, logs, receipt, summaryWrites };
}

describe("acceptance close selects authenticated landed evidence (#2068)", () => {
  it("pins the checkout and command to the selector, before installing or running repository code", () => {
    const spec = workflow();
    expect(spec.on.issues.types).toContain("closed");
    expect(spec.on.workflow_dispatch.inputs).toHaveProperty("issue");
    const { permissions, steps } = spec.jobs["acceptance-close"];
    expect(permissions).toEqual({ contents: "read", issues: "write", "pull-requests": "read" });
    expect(steps[0]?.id).toBe("evidence-revision");
    expect(steps[1]?.uses).toBe("actions/checkout@v4");
    expect(steps[1]?.with).toEqual({ ref: "${{ steps.evidence-revision.outputs.sha }}", "persist-credentials": false });
    const gate = steps.find((s) => s.name === "Acceptance conservation on close")!;
    expect(gate.env?.CLOSED_ISSUE).toBe("${{ steps.evidence-revision.outputs.issue }}");
    expect(gate.env?.ACCEPTANCE_REPOSITORY).toBe("${{ github.repository }}");
    expect(gate.run).toContain('--closed-issue "$CLOSED_ISSUE"');
    expect(gate.run).toContain('--repo "$ACCEPTANCE_REPOSITORY"');
    expect(gate.run).toContain("--act");
    expect(gate.if).toBe("${{ !inputs.liveness_drill }}");
    expect(steps.find((s) => s.run?.includes("--selftest-close"))?.if).toBe(gate.if);
    expect(steps.at(-1)?.if).toBe("always()");
    expect(steps.at(-1)?.with?.expect).toBe("acceptance-close-selftest, acceptance-close");
  });

  it.each([
    { event: "issues", eventSha: OLD, name: "stale issue event" },
    { event: "issues", eventSha: TIP, name: "ordinary merge close" },
    { event: "workflow_dispatch", eventSha: SOURCE, name: "dispatch from the implementation ref" },
  ])("selects and records the trusted tip for $name", async ({ event, eventSha }) => {
    const result = await select({ event, eventSha });
    expect(result.outputs).toEqual({ sha: TIP, issue: "700" });
    expect(result.comparisons).toEqual([`${MERGE}...${TIP}`]);
    expect(result.receipt).toMatchObject({ workflowSourceSha: SOURCE, suppliedEventSha: eventSha, selectedEvidenceSha: TIP, event,
      selectionReason: "Authenticated default-branch tip contains every linked merge into this default branch",
      verifiedMerges: [{ number: 900, mergeCommit: MERGE }] });
    expect(result.summaryWrites).toBe(1);
    expect(result.logs.join("\n")).toContain(TIP);
  });

  it("uses the trusted default branch for a manual close with no linked PR", async () => {
    const result = await select({ pages: [[]] });
    expect(result.outputs.sha).toBe(TIP);
    expect(result.comparisons).toEqual([]);
    expect(result.receipt?.selectionReason).toBe("Authenticated default-branch tip; no linked merge into this default branch");
  });

  it("reads all pages including merged PRs and checks every eligible merge", async () => {
    const result = await select({ pages: [[merged()], [merged(901, OLD)]] });
    expect(result.queries).toHaveLength(2);
    expect(result.queries[0]?.query).toContain("includeClosedPrs: true");
    expect(result.queries[0]?.query).toContain("after: $after");
    expect(result.queries[1]?.variables.after).toBe("page-0");
    expect(result.comparisons).toEqual([`${MERGE}...${TIP}`, `${OLD}...${TIP}`]);
  });

  it("never selects code from foreign, unmerged or non-default linked PRs", async () => {
    const result = await select({ pages: [[
      { ...merged(901), repository: { nameWithOwner: "outsider/widgets" } },
      { ...merged(902), merged: false },
      { ...merged(903), baseRefName: "release" },
    ]] });
    expect(result.outputs.sha).toBe(TIP);
    expect(result.comparisons).toEqual([]);
    expect(result.receipt?.otherLinks).toEqual([
      { number: 901, repository: "outsider/widgets", reason: "different repository" },
      { number: 902, repository: REPO, reason: "not merged" },
      { number: 903, repository: REPO, reason: "different base branch" },
    ]);
    expect(result.queries[0]?.query).not.toMatch(/headRef|headRepository/);
  });

  it.each(["behind", "diverged"])("refuses an authenticated tip that is %s the linked merge", async (status) => {
    await expect(select({ compare: (base) => ({ status, base_commit: { sha: base }, merge_base_commit: { sha: OLD } }) })).rejects.toThrow("does not contain linked PR #900");
  });

  it("does not accept a plausible status whose merge-base identity disagrees", async () => {
    await expect(select({ compare: (base) => ({ status: "ahead", base_commit: { sha: base }, merge_base_commit: { sha: OLD } }) })).rejects.toThrow("does not contain linked PR #900");
  });

  it.each([
    { name: "repository mismatch", change: (r: Record<string, unknown>) => { r.nameWithOwner = "outsider/widgets"; } },
    { name: "missing branch", change: (r: Record<string, unknown>) => { r.defaultBranchRef = null; } },
    { name: "branch instead of SHA", change: (r: Record<string, unknown>) => { r.defaultBranchRef = { name: "main", target: { __typename: "Commit", oid: "main" } }; } },
    { name: "missing issue", change: (r: Record<string, unknown>) => { r.issue = null; } },
    { name: "missing pagination", change: (r: Record<string, unknown>) => { r.issue = { number: 700, closedByPullRequestsReferences: { nodes: [] } }; } },
  ])("fails closed on $name", async ({ change }) => {
    await expect(select({ response: (value) => { change(value.repository as Record<string, unknown>); return value; } })).rejects.toThrow();
  });

  it("rejects repeated pagination instead of silently dropping linked merges", async () => {
    await expect(select({ response: (value) => {
      const record = value.repository as { issue: { closedByPullRequestsReferences: { pageInfo: unknown } } };
      record.issue.closedByPullRequestsReferences.pageInfo = { hasNextPage: true, endCursor: "stuck" };
      return value;
    } })).rejects.toThrow("pagination did not advance");
  });

  it.each([
    { ...merged(), mergeCommit: { oid: "" } },
    { ...merged(), repository: { nameWithOwner: "" } },
  ])("refuses incomplete linked-PR trust metadata", async (pr) => {
    await expect(select({ pages: [[pr]] })).rejects.toThrow();
  });

  it("propagates authentication or API failures without emitting a fallback revision", async () => {
    await expect(select({ response: () => { throw new Error("401 authentication failed"); } })).rejects.toThrow("401 authentication failed");
  });

  it("requires the workflow source identity separately from the event and selected evidence SHAs", async () => {
    await expect(select({ sourceSha: "" })).rejects.toThrow("Missing workflow source SHA");
  });

  it.each(["0", "-1", "700; touch /tmp/injected", "9007199254740992"])("rejects invalid dispatch issue %s before any API call", async (inputIssue) => {
    await expect(select({ event: "workflow_dispatch", inputIssue, response: () => { throw new Error("API must not be called"); } })).rejects.toThrow("positive issue number");
  });

  it.each([true, "true"])("keeps liveness drill %s free of issue reads even with a deliberately ignored issue input", async (drill) => {
    const result = await select({ event: "workflow_dispatch", drill, inputIssue: "ignored" });
    expect(result.queries[0]?.variables.drill).toBe(true);
    expect(result.queries[0]?.query).toContain("@skip(if: $drill)");
    expect(result.outputs).toEqual({ sha: TIP, issue: "" });
    expect(result.comparisons).toEqual([]);
    expect(result.receipt?.issue).toBeNull();
  });
});

describe("selected Git tree reaches the real close validator and its actions (#2068)", () => {
  let fixture: string;
  let history: string;
  let old: string;
  let landed: string;
  let runNumber = 0;
  const git = (...args: string[]) => execFileSync("git", args, { cwd: history, encoding: "utf8" }).trim();

  beforeAll(() => {
    fixture = mkdtempSync(join(tmpdir(), "harvey-evidence-revision-"));
    history = join(fixture, "history");
    mkdirSync(join(history, "src/cli"), { recursive: true });
    // These are the production CLI and its local imports, copied byte-for-byte. No cited evidence
    // file exists until the second real commit; neither fixture code nor dependencies are run by Git.
    for (const file of ["package.json", "src/cli/validate-acceptance.ts", "src/cli/sync-stdio.ts", "src/acceptance-conservation.ts", "src/fs-walk.ts", "src/ci-liveness.ts", "src/secret-argv.ts"]) {
      copyFileSync(join(ROOT, file), join(history, file));
    }
    git("init", "-q");
    git("add", ".");
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "Before evidence landed");
    old = git("rev-parse", "HEAD");
    writeFileSync(join(history, "src/landed-evidence.ts"), "export const delivered = true;\n");
    git("add", ".");
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "Land acceptance evidence");
    landed = git("rev-parse", "HEAD");
  });

  afterAll(() => { if (fixture) rmSync(fixture, { recursive: true, force: true }); });

  const compare = (base: string, head: string): Comparison => {
    const ancestor = git("merge-base", base, head);
    return { status: base === head ? "identical" : ancestor === base ? "ahead" : "behind", base_commit: { sha: base }, merge_base_commit: { sha: ancestor } };
  };

  // Replay checkout's default-to-event behavior as well as the explicit step output. Removing the
  // workflow's ref binding must make the physical regression below fail on the old files.
  function checkoutRevision(selection: { outputs: Record<string, string> }, eventSha = OLD): string {
    const ref = workflow().jobs["acceptance-close"].steps.find((step) => step.uses === "actions/checkout@v4")?.with?.ref;
    if (ref === undefined) return eventSha;
    if (ref === "${{ steps.evidence-revision.outputs.sha }}") return selection.outputs.sha!;
    if (typeof ref === "string" && /^[0-9a-f]{40}$/.test(ref)) return ref;
    throw new Error(`Unsupported checkout reference in test: ${String(ref)}`);
  }

  async function validate(revision: string, options: { manual?: boolean; missing?: boolean; duplicate?: boolean; foreign?: boolean } = {}) {
    const dir = join(fixture, `run-${runNumber++}`);
    mkdirSync(dir);
    execFileSync("tar", ["-x", "-C", dir], { input: execFileSync("git", ["archive", revision], { cwd: history }) });
    symlinkSync(join(ROOT, "node_modules"), join(dir, "node_modules"), "dir");
    const body = options.missing ? DISPOSITION.replace("landed-evidence.ts", "never-landed.ts") : DISPOSITION;
    const issue = {
      number: 700, state: "CLOSED", body: "## Acceptance\n- the delivered change exists\n",
      author: { login: "operator", is_bot: false }, labels: [{ name: "acceptance-unaccounted" }],
      comments: options.manual || options.duplicate ? [{ body }] : [],
      closedByPullRequestsReferences: options.manual ? [] : [{ number: 900, repository: { name: "widgets", owner: { login: options.foreign ? "outsider" : "acme" } } }],
    };
    writeFileSync(join(dir, "issue.json"), JSON.stringify(issue));
    writeFileSync(join(dir, "pr.json"), JSON.stringify({ body }));
    const bin = join(dir, "bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "package.json"), '{"type":"commonjs"}\n');
    writeFileSync(join(bin, "gh"), `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.HARVEY_EVIDENCE_CALLS, JSON.stringify(args) + '\\n');
if (args[1] !== 'view') {
  if (args[1] === 'comment') fs.writeFileSync(process.env.HARVEY_EVIDENCE_COMMENT, fs.readFileSync(0));
  process.exit(0);
}
const value = JSON.parse(fs.readFileSync(args[0] + '.json', 'utf8'));
if (args.includes('--jq')) { process.stdout.write(value.labels.map(l => l.name).join(',')); process.exit(0); }
const fields = args[args.indexOf('--json') + 1].split(',');
process.stdout.write(JSON.stringify(Object.fromEntries(fields.filter(f => f in value).map(f => [f, value[f]]))));
`);
    chmodSync(join(bin, "gh"), 0o755);
    const calls = join(dir, "calls.jsonl");
    const comment = join(dir, "comment.txt");
    writeFileSync(calls, "");
    const result = await new Promise<{ code: number; out: string }>((done, reject) => {
      const child = spawn(process.execPath, ["--import", join(ROOT, "node_modules/tsx/dist/loader.mjs"), join(dir, "src/cli/validate-acceptance.ts"), "--closed-issue", "700", "--repo", REPO, "--act"], {
        cwd: dir, stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_LIVENESS_RECEIPT: join(dir, "receipt"), HARVEY_EVIDENCE_CALLS: calls, HARVEY_EVIDENCE_COMMENT: comment },
      });
      let out = "";
      child.stdout.on("data", (chunk: Buffer) => { out += chunk.toString(); });
      child.stderr.on("data", (chunk: Buffer) => { out += chunk.toString(); });
      child.once("error", reject);
      child.once("close", (code) => done({ code: code ?? -1, out }));
    });
    return { ...result, calls: readFileSync(calls, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as string[]), dir };
  }

  it("a stale event selects the landed physical tree; choosing the old tree reproduces the false missing-file failure", async () => {
    const selection = await select({ tip: landed, eventSha: old, pages: [[merged(900, landed)]], compare });
    const checked = await validate(checkoutRevision(selection, old));
    expect(checked.code, checked.out).toBe(0);
    expect(checked.calls).toContainEqual(["issue", "edit", "700", "--repo", REPO, "--remove-label", "acceptance-unaccounted"]);
    expect(checked.calls.some((args) => args[1] === "reopen")).toBe(false);
    const stale = await validate(old);
    expect(stale.code, stale.out).toBe(1);
    expect(stale.out).toContain("`src/landed-evidence.ts`, which does not exist in this checkout");
    expect(stale.calls).toContainEqual(["issue", "reopen", "700", "--repo", REPO]);
    expect(readFileSync(join(stale.dir, "comment.txt"), "utf8")).toContain("src/landed-evidence.ts");
  });

  it("genuinely absent evidence still fails in the correct tree and reopens an already-labelled issue", async () => {
    const selection = await select({ tip: landed, pages: [[merged(900, landed)]], compare });
    const checked = await validate(checkoutRevision(selection), { missing: true });
    expect(checked.code, checked.out).toBe(1);
    expect(checked.out).toContain("`src/never-landed.ts`, which does not exist in this checkout");
    expect(checked.calls).toContainEqual(["issue", "reopen", "700", "--repo", REPO]);
    expect(checked.calls).toContainEqual(["issue", "edit", "700", "--repo", REPO, "--add-label", "acceptance-unaccounted"]);
  });

  it.each(["issues", "workflow_dispatch"])("the normal %s path validates landed evidence and removes the failure label", async (event) => {
    const selection = await select({ event, eventSha: event === "issues" ? landed : SOURCE, tip: landed, pages: [[merged(900, landed)]], compare });
    const checked = await validate(checkoutRevision(selection, event === "issues" ? landed : SOURCE));
    expect(checked.code, checked.out).toBe(0);
    expect(checked.calls).toContainEqual(["issue", "edit", "700", "--repo", REPO, "--remove-label", "acceptance-unaccounted"]);
  });

  it("manual-close comments remain the evidence venue in the selected tree", async () => {
    const selection = await select({ tip: landed, pages: [[]] });
    const checked = await validate(checkoutRevision(selection), { manual: true });
    expect(checked.code, checked.out).toBe(0);
    expect(checked.calls.some((args) => args[0] === "pr")).toBe(false);
  });

  it("duplicate dispositions still fail across the linked PR and issue comment", async () => {
    const selection = await select({ tip: landed, pages: [[merged(900, landed)]], compare });
    const checked = await validate(checkoutRevision(selection), { duplicate: true });
    expect(checked.code, checked.out).toBe(1);
    expect(checked.out).toContain("mapped 2 times");
    expect(checked.calls).toContainEqual(["issue", "reopen", "700", "--repo", REPO]);
  });

  it("a foreign linked PR remains a correctly addressed disposition venue without supplying the evidence tree", async () => {
    const selection = await select({ tip: landed, pages: [[{ ...merged(), repository: { nameWithOwner: "outsider/widgets" } }]] });
    const checked = await validate(checkoutRevision(selection), { foreign: true });
    expect(checked.code, checked.out).toBe(0);
    expect(checked.calls).toContainEqual(["pr", "view", "900", "--repo", "outsider/widgets", "--json", "body"]);
  });
});
