import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { isFocusedLocalVerificationPath, localVerificationTier } from "./local-verify.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LOCAL_VERIFY = join(REPO_ROOT, "src", "local-verify.ts");
const created: string[] = [];

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function git(dir: string, args: string[]): string {
  return execFileSync("git", args, { cwd: dir, encoding: "utf8" }).trim();
}

function fixture(changes: Record<string, string>, options: { failDiff?: boolean; failDiffCheck?: boolean } = {}): { root: string; base: string; marker: string; gitMarker: string; bin: string } {
  const root = mkdtempSync(join(tmpdir(), "harvey-local-verify-"));
  created.push(root);
  git(root, ["init", "-q", "-b", "main"]);
  git(root, ["config", "user.name", "Fixture"]);
  git(root, ["config", "user.email", "fixture@example.test"]);
  writeFileSync(join(root, "seed"), "base\n");
  for (const path of Object.keys(changes)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, "baseline\n");
  }
  git(root, ["add", "."]);
  git(root, ["commit", "-qm", "base"]);
  const base = git(root, ["rev-parse", "HEAD"]);
  for (const [path, body] of Object.entries(changes)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  }

  // The real entrypoint is executed from this disposable Git repository. Its pnpm/python children
  // are tiny controlled executables, so the marker records the actual selected argv without running
  // a suite or altering this checkout.
  const bin = join(root, "controlled-bin");
  mkdirSync(bin);
  const marker = join(root, "children");
  const gitMarker = join(root, "git-calls");
  const child = [
    "#!/bin/sh",
    'printf "%s %s\\n" "$(basename "$0")" "$*" >> "$HARVEY_LOCAL_VERIFY_MARKER"',
    '[ "$HARVEY_LOCAL_VERIFY_FAIL" = "$(basename "$0")" ] && exit 37',
    "exit 0",
  ].join("\n");
  const pnpm = join(bin, "pnpm");
  writeFileSync(pnpm, child);
  execFileSync("chmod", ["+x", pnpm]);
  const realPython = execFileSync("which", ["python3"], { encoding: "utf8" }).trim();
  const python = join(bin, "python3");
  writeFileSync(python, [
    "#!/bin/sh",
    'printf "%s %s\\n" "$(basename "$0")" "$*" >> "$HARVEY_LOCAL_VERIFY_MARKER"',
    'exec "' + realPython + '" "$@"',
  ].join("\n"));
  execFileSync("chmod", ["+x", python]);
  const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
  writeFileSync(join(bin, "git"), [
    "#!/bin/sh",
    'printf "%s\\n" "$*" >> "$HARVEY_LOCAL_VERIFY_GIT_MARKER"',
    options.failDiff ? '[ "$1" = diff ] && exit 2' : "",
    options.failDiffCheck ? '[ "$1" = diff ] && [ "$2" = --check ] && exit 23' : "",
    'exec "' + realGit + '" "$@"',
  ].filter(Boolean).join("\n"));
  execFileSync("chmod", ["+x", join(bin, "git")]);
  symlinkSync(join(REPO_ROOT, "node_modules"), join(root, "node_modules"), "dir");
  return { root, base, marker, gitMarker, bin };
}

function runFixture(f: ReturnType<typeof fixture>, options: { base?: string; fail?: string } = {}) {
  return spawnSync(process.execPath, ["--import", "tsx", LOCAL_VERIFY], {
    cwd: f.root,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: f.bin + ":" + process.env.PATH,
      HARVEY_VERIFY_BASE: options.base ?? f.base,
      HARVEY_LOCAL_VERIFY_MARKER: f.marker,
      HARVEY_LOCAL_VERIFY_GIT_MARKER: f.gitMarker,
      HARVEY_LOCAL_VERIFY_FAIL: options.fail ?? "",
    },
  });
}

function marker(path: string): string[] {
  try {
    return readFileSync(path, "utf8").trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

describe("path-sensitive local verification", () => {
  it("uses the focused gate for operating docs, Markdown docs, and Codex agent TOML", () => {
    for (const path of [
      "AGENTS.md",
      "CLAUDE.md",
      "MODULES.md",
      "README.md",
      "SESSION.md",
      "docs/design/recorded-reasons.md",
      ".codex/agents/acceptance-verifier.toml",
    ]) {
      expect(isFocusedLocalVerificationPath(path), path).toBe(true);
    }
    expect(localVerificationTier(["AGENTS.md", "SESSION.md", ".codex/agents/acceptance-verifier.toml"])).toBe("focused");
  });

  it("fails safe to the full gate for source, executable inputs, manifests, workflows, and unknown paths", () => {
    for (const path of [
      "src/findings.ts",
      "briefs/anti-patterns.md",
      "targets/calibration/README.md",
      "package.json",
      "pnpm-lock.yaml",
      ".github/workflows/ci.yml",
      ".github/actions/alert-issue/action.yml",
      "dry-run/findings.json",
      ".codex/config.toml",
      ".codex/agents/unclassified.txt",
      ".codex/agents/team/nested.toml",
      "docs/data.json",
      "notes.txt",
    ]) {
      expect(isFocusedLocalVerificationPath(path), path).toBe(false);
      expect(localVerificationTier([path]), path).toBe("full");
    }
  });

  it("takes the widest tier for mixed changes and treats an empty diff as full", () => {
    expect(localVerificationTier(["SESSION.md", "src/findings.ts"])).toBe("full");
    expect(localVerificationTier([])).toBe("full");
  });
});

describe("local-verify CLI entrypoint", () => {
  it("selects the focused sequence from an actual Git diff and passes HARVEY_VERIFY_BASE to git", () => {
    const f = fixture({
      "docs/policy.md": "changed\n",
      ".codex/agents/check.toml": 'name = "check"\n',
    });
    const result = runFixture(f);
    expect(result.status, result.stderr).toBe(0);
    expect(marker(f.marker)).toEqual([
      "python3 -c import sys,tomllib; [tomllib.load(open(path,'rb')) for path in sys.argv[1:]] .codex/agents/check.toml",
      "pnpm exec vitest run src/local-verify.test.ts src/recorded-reasons.test.ts src/ci-tier-router.test.ts src/corpus-tier-router.test.ts",
    ]);
    expect(marker(f.gitMarker)).toContain("merge-base " + f.base + " HEAD");
    expect(marker(f.gitMarker)).toContain("diff --name-only " + f.base);
    expect(marker(f.gitMarker)).toContain("diff --check " + f.base);
  });

  it("selects the full gate for source, mixed, empty, missing-base, and failed-diff states", () => {
    for (const f of [
      fixture({ "src/example.ts": "export {};\n" }),
      fixture({ "docs/policy.md": "changed\n", "src/example.ts": "export {};\n" }),
      fixture({}),
      fixture({ "docs/policy.md": "changed\n" }, { failDiff: true }),
    ]) {
      const result = runFixture(f);
      expect(result.status, result.stderr).toBe(0);
      expect(marker(f.marker)).toEqual(["pnpm verify"]);
    }
    const missing = fixture({ "docs/policy.md": "changed\n" });
    const missingResult = runFixture(missing, { base: "definitely-not-a-ref" });
    expect(missingResult.status, missingResult.stderr).toBe(0);
    expect(marker(missing.marker)).toEqual(["pnpm verify"]);
  });

  it("propagates malformed TOML child failure and stops before the focused suite", () => {
    const f = fixture({ ".codex/agents/broken.toml": "not = [valid\n" });
    const result = runFixture(f);
    expect(result.status).toBe(1);
    expect(marker(f.marker)).toEqual(["python3 -c import sys,tomllib; [tomllib.load(open(path,'rb')) for path in sys.argv[1:]] .codex/agents/broken.toml"]);
  });

  it("propagates a diff-hygiene child failure and stops before TOML parsing or the suite", () => {
    const f = fixture({ ".codex/agents/check.toml": 'name = "check"\n' }, { failDiffCheck: true });
    const result = runFixture(f);
    expect(result.status).toBe(23);
    expect(marker(f.marker)).toEqual([]);
    expect(marker(f.gitMarker)).toContain("diff --check " + f.base);
  });

  it("propagates a deliberate selected-child failure", () => {
    const f = fixture({ "src/example.ts": "export {};\n" });
    const result = runFixture(f, { fail: "pnpm" });
    expect(result.status).toBe(37);
    expect(marker(f.marker)).toEqual(["pnpm verify"]);
  });
});
