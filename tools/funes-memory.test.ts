import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(REPO_ROOT, "tools", "funes-memory.ts");
const TSX_LOADER = createRequire(import.meta.url).resolve("tsx/esm");
const SCRATCH: string[] = [];

interface IndexFixture {
  id: string;
  date: string;
  summary?: string;
}

interface FakeCall {
  argv: string[];
  env: Record<string, { present: boolean; value: string | null }>;
  sourceExists: boolean;
}

afterEach(() => {
  for (const path of SCRATCH.splice(0)) rmSync(path, { recursive: true, force: true });
});

function fixtureRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "harvey-funes-memory-")));
  SCRATCH.push(root);
  return root;
}

function writeIndexes(root: string, lean: readonly IndexFixture[], archive: readonly IndexFixture[]): void {
  const render = (title: string, entries: readonly IndexFixture[]): string =>
    [
      `# ${title}`,
      "",
      "## Entries",
      "",
      ...entries.map((entry) => `- ${entry.id} — ${entry.date} — ${entry.summary ?? `Summary for ${entry.id}`}`),
      "",
    ].join("\n");
  writeFileSync(join(root, "MEMORY-INDEX.md"), render("Lean", lean));
  writeFileSync(join(root, "MEMORY-INDEX-ARCHIVE.md"), render("Archive", archive));
}

function writeFixture(
  root: string,
  memory: string,
  lean: readonly IndexFixture[],
  archive: readonly IndexFixture[] = [],
): void {
  writeFileSync(join(root, "MEMORY.md"), memory);
  writeIndexes(root, lean, archive);
}

function runCli(root: string, args: readonly string[], env: NodeJS.ProcessEnv = {}): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, ["--import", TSX_LOADER, CLI, ...args], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 20_000,
  });
}

function expectSuccess(result: ReturnType<typeof spawnSync>): void {
  expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
}

function generatedPath(root: string, id: string): string {
  return join(root, ".funes-harvey", "source", `${id}.jsonl`);
}

function installFakeFunes(root: string, version = "1.3.0", commandStatus = 0): { bin: string; log: string } {
  const fakeDirectory = join(root, "fake bin; no shell");
  mkdirSync(fakeDirectory);
  const bin = join(fakeDirectory, "funes executable.cjs");
  const log = join(root, "fake-funes.jsonl");
  const watched = [
    "FUNES_BIN",
    "FUNES_HOME",
    "FUNES_MEMORY",
    "FUNES_TRUFFLEHOG",
    "HF_HOME",
    "HF_HUB_CACHE",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "HUGGINGFACE_TOKEN",
  ];
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const argv = process.argv.slice(2);
const watched = ${JSON.stringify(watched)};
const env = Object.fromEntries(watched.map((name) => [name, {
  present: Object.prototype.hasOwnProperty.call(process.env, name),
  value: process.env[name] ?? null,
}]));
const sourceExists = process.env.FAKE_EXPECT_SOURCE
  ? fs.existsSync(process.env.FAKE_EXPECT_SOURCE)
  : false;
fs.appendFileSync(process.env.FAKE_FUNES_LOG, JSON.stringify({ argv, env, sourceExists }) + "\\n");
if (argv.length === 1 && argv[0] === "--version") {
  process.stdout.write(${JSON.stringify(`funes ${version}\n`)});
} else {
  process.exitCode = ${commandStatus};
}
`,
  );
  chmodSync(bin, 0o755);
  return { bin, log };
}

function fakeCalls(log: string): FakeCall[] {
  return readFileSync(log, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FakeCall);
}

const FIRST_ENTRY = [
  "## D-001 — 2026-08-03 — Preserve the boundary",
  "",
  "The horizontal rule below is content, not a record delimiter.",
  "",
  "---",
  "",
  "This remains in D-001.",
  "",
].join("\n");

const SUFFIXED_ENTRY = [
  "## D-002a — 2026-08-04 — Keep the suffix",
  "",
  "There is no separator between this header and the prior decision slice.",
  "",
].join("\n");

describe("funes-memory export", () => {
  it("emits exact stable Codex records, keeps separators, and supports suffixed IDs", () => {
    const root = fixtureRoot();
    mkdirSync(join(root, "SESSION.md"));
    writeFixture(
      root,
      `# Harvey memory\n\n${FIRST_ENTRY}${SUFFIXED_ENTRY}`,
      [{ id: "D-001", date: "2026-08-03" }],
      [{ id: "D-002a", date: "2026-08-04" }],
    );

    const result = runCli(root, ["export"]);
    expectSuccess(result);
    expect(result.stdout).toContain("2 added, 0 unchanged");

    const firstExpected = `${JSON.stringify({
      timestamp: "2026-08-03T00:00:00.000Z",
      type: "session_meta",
      payload: { id: "harvey-memory-D-001", cwd: "/Harvey" },
    })}\n${JSON.stringify({
      timestamp: "2026-08-03T00:00:00.000Z",
      type: "response_item",
      payload: {
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: FIRST_ENTRY }],
      },
    })}\n`;
    expect(readFileSync(generatedPath(root, "D-001"), "utf8")).toBe(firstExpected);
    expect(readFileSync(generatedPath(root, "D-002a"), "utf8")).toContain(
      '"id":"harvey-memory-D-002a"',
    );
    expect(JSON.parse(readFileSync(generatedPath(root, "D-002a"), "utf8").split("\n")[1] ?? "null"))
      .toEqual({
        timestamp: "2026-08-04T00:00:00.000Z",
        type: "response_item",
        payload: {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: SUFFIXED_ENTRY }],
        },
      });
  });

  it.each([
    ["malformed ID", "## D-nope — 2026-08-03 — Bad\n\nBody\n", "malformed decision header"],
    [
      "duplicate ID",
      "## D-001 — 2026-08-03 — First\n\nOne\n\n## D-001 — 2026-08-04 — Again\n\nTwo\n",
      "duplicate decision ID D-001",
    ],
    ["invalid date", "## D-001 — 2026-02-30 — Impossible\n\nBody\n", "invalid calendar date"],
  ])("rejects a %s", (_name, memory, message) => {
    const root = fixtureRoot();
    writeFixture(root, memory, [{ id: "D-001", date: "2026-08-03" }]);
    const result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
    expect(existsSync(join(root, ".funes-harvey"))).toBe(false);
  });

  it.each([
    [
      "a missing index ID",
      [{ id: "D-001", date: "2026-08-03" }],
      [] as IndexFixture[],
      "missing from indexes: D-002a",
    ],
    [
      "an unknown index ID",
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-04" },
        { id: "D-999", date: "2026-08-05" },
      ],
      [] as IndexFixture[],
      "not present in MEMORY.md: D-999",
    ],
    [
      "overlap between indexes",
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-04" },
      ],
      [{ id: "D-001", date: "2026-08-03" }],
      "indexes overlap: D-001",
    ],
    [
      "a mismatched index date",
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-05" },
      ],
      [] as IndexFixture[],
      "D-002a index=2026-08-05 memory=2026-08-04",
    ],
  ])("rejects %s", (_name, lean, archive, message) => {
    const root = fixtureRoot();
    writeFixture(root, `${FIRST_ENTRY}${SUFFIXED_ENTRY}`, lean, archive);
    const result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
  });

  it("rejects malformed and duplicate rows inside an index", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    writeFileSync(
      join(root, "MEMORY-INDEX.md"),
      "# Lean\n\n## Entries\n\n- D-001 — 2026-08-03 — First\n- D-001 — 2026-08-03 — Again\n",
    );
    let result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("duplicate decision ID D-001");

    writeFileSync(join(root, "MEMORY-INDEX.md"), "# Lean\n\n## Entries\n\n- D-wrong — 2026-08-03 — Bad\n");
    result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("malformed index entry");
  });

  it("leaves identical historical bytes and mtime untouched", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    expectSuccess(runCli(root, ["export"]));
    const path = generatedPath(root, "D-001");
    const before = readFileSync(path);
    const oldTime = new Date("2001-02-03T04:05:06.000Z");
    utimesSync(path, oldTime, oldTime);
    const mtime = lstatSync(path, { bigint: true }).mtimeNs;

    const second = runCli(root, ["export"]);
    expectSuccess(second);
    expect(second.stdout).toContain("0 added, 1 unchanged");
    expect(readFileSync(path).equals(before)).toBe(true);
    expect(lstatSync(path, { bigint: true }).mtimeNs).toBe(mtime);
  });

  it("adds a new decision without rewriting the historical source", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    expectSuccess(runCli(root, ["export"]));
    const firstPath = generatedPath(root, "D-001");
    const firstBytes = readFileSync(firstPath);
    const oldTime = new Date("2002-03-04T05:06:07.000Z");
    utimesSync(firstPath, oldTime, oldTime);
    const firstMtime = lstatSync(firstPath, { bigint: true }).mtimeNs;

    writeFixture(
      root,
      `${FIRST_ENTRY}${SUFFIXED_ENTRY}`,
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-04" },
      ],
    );
    const addition = runCli(root, ["export"]);
    expectSuccess(addition);
    expect(addition.stdout).toContain("1 added, 1 unchanged");
    expect(readFileSync(firstPath).equals(firstBytes)).toBe(true);
    expect(lstatSync(firstPath, { bigint: true }).mtimeNs).toBe(firstMtime);
    expect(existsSync(generatedPath(root, "D-002a"))).toBe(true);
  });

  it("refuses a historical mutation before writing a new decision", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    expectSuccess(runCli(root, ["export"]));
    const original = readFileSync(generatedPath(root, "D-001"));

    writeFixture(
      root,
      `${FIRST_ENTRY.replace("horizontal rule", "changed rule")}${SUFFIXED_ENTRY}`,
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-04" },
      ],
    );
    const result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("historical generated file was modified: D-001.jsonl");
    expect(readFileSync(generatedPath(root, "D-001")).equals(original)).toBe(true);
    expect(existsSync(generatedPath(root, "D-002a"))).toBe(false);
  });

  it("refuses removal of a previously exported decision", () => {
    const root = fixtureRoot();
    writeFixture(
      root,
      `${FIRST_ENTRY}${SUFFIXED_ENTRY}`,
      [
        { id: "D-001", date: "2026-08-03" },
        { id: "D-002a", date: "2026-08-04" },
      ],
    );
    expectSuccess(runCli(root, ["export"]));
    writeFixture(root, SUFFIXED_ENTRY, [{ id: "D-002a", date: "2026-08-04" }]);

    const result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("generated file for removed decision D-001 still exists");
  });

  it("refuses unexplained extras in the generated source directory", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    expectSuccess(runCli(root, ["export"]));
    writeFileSync(join(root, ".funes-harvey", "source", "notes.txt"), "not generated");

    const result = runCli(root, ["export"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("unexplained extra in source directory: notes.txt");
  });
});

describe("funes-memory process boundary", () => {
  it("exports before indexing, pins exact argv/version, and sanitizes the child environment", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    const fake = installFakeFunes(root);
    const source = generatedPath(root, "D-001");
    const result = runCli(root, ["index"], {
      FUNES_BIN: fake.bin,
      FUNES_MEMORY: "hf://datasets/attacker/remote",
      FUNES_TRUFFLEHOG: "/tmp/untrusted-trufflehog",
      HF_HUB_CACHE: "/tmp/outside-cache",
      HF_TOKEN: "hf-secret-one",
      HUGGING_FACE_HUB_TOKEN: "hf-secret-two",
      HUGGINGFACE_TOKEN: "hf-secret-three",
      FAKE_FUNES_LOG: fake.log,
      FAKE_EXPECT_SOURCE: source,
    });
    expectSuccess(result);

    const calls = fakeCalls(fake.log);
    expect(calls.map((call) => call.argv)).toEqual([
      ["--version"],
      [
        "index",
        join(root, ".funes-harvey", "source"),
        "--harness",
        "codex",
        "--yes",
        "--no-thinking",
      ],
    ]);
    for (const call of calls) {
      expect(call.sourceExists).toBe(true);
      expect(call.env.FUNES_HOME).toEqual({
        present: true,
        value: join(root, ".funes-harvey", "funes"),
      });
      expect(call.env.HF_HOME).toEqual({
        present: true,
        value: join(root, ".funes-harvey", "huggingface"),
      });
      for (const name of [
        "FUNES_BIN",
        "FUNES_MEMORY",
        "FUNES_TRUFFLEHOG",
        "HF_HUB_CACHE",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "HUGGINGFACE_TOKEN",
      ]) {
        expect(call.env[name], name).toEqual({ present: false, value: null });
      }
    }
  });

  it("requires exactly Funes 1.3.0 after completing the source export", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    const fake = installFakeFunes(root, "1.3.1");
    const result = runCli(root, ["index"], {
      FUNES_BIN: fake.bin,
      FAKE_FUNES_LOG: fake.log,
      FAKE_EXPECT_SOURCE: generatedPath(root, "D-001"),
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Funes 1.3.0 is required");
    expect(existsSync(generatedPath(root, "D-001"))).toBe(true);
    expect(fakeCalls(fake.log).map((call) => call.argv)).toEqual([["--version"]]);
  });

  it("pins recall to local memory and treats a leading --memory as query text", () => {
    const root = fixtureRoot();
    const fake = installFakeFunes(root);
    const result = runCli(root, ["recall", "--memory", "hf://datasets/attacker/remote"], {
      FUNES_BIN: fake.bin,
      FUNES_MEMORY: "hf://datasets/attacker/environment",
      HF_TOKEN: "do-not-forward",
      FAKE_FUNES_LOG: fake.log,
    });
    expectSuccess(result);
    const calls = fakeCalls(fake.log);
    expect(calls.map((call) => call.argv)).toEqual([
      ["--version"],
      [
        "recall",
        "--memory",
        "local",
        "--half-life",
        "0",
        "--",
        "--memory hf://datasets/attacker/remote",
      ],
    ]);
    for (const call of calls) {
      expect(call.env.FUNES_MEMORY).toEqual({ present: false, value: null });
      expect(call.env.HF_TOKEN).toEqual({ present: false, value: null });
    }
  });

  it("rejects an empty recall query before invoking Funes", () => {
    const root = fixtureRoot();
    const result = runCli(root, ["recall", "", "   "]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("recall requires a non-empty query");
    expect(existsSync(join(root, ".funes-harvey"))).toBe(false);
  });

  it.each(["add", "push", "ask", "mcp"])("does not expose the Funes %s path", (command) => {
    const root = fixtureRoot();
    const result = runCli(root, [command]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("expected export, index, or recall");
    expect(existsSync(join(root, ".funes-harvey"))).toBe(false);
  });

  it("propagates a Funes command failure without rewriting exported sources", () => {
    const root = fixtureRoot();
    writeFixture(root, FIRST_ENTRY, [{ id: "D-001", date: "2026-08-03" }]);
    const fake = installFakeFunes(root, "1.3.0", 7);
    const result = runCli(root, ["index"], {
      FUNES_BIN: fake.bin,
      FAKE_FUNES_LOG: fake.log,
    });
    expect(result.status).toBe(7);
    expect(result.stderr).toContain("Funes exited 7");
    expect(existsSync(generatedPath(root, "D-001"))).toBe(true);
  });
});
