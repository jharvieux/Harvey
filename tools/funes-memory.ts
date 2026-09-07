import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { readEntriesLstatSafe } from "../src/fs-walk.js";

const REQUIRED_FUNES_VERSION = "1.3.0";
const MEMORY_FILE = "MEMORY.md";
const LEAN_INDEX_FILE = "MEMORY-INDEX.md";
const ARCHIVE_INDEX_FILE = "MEMORY-INDEX-ARCHIVE.md";
const DECISION_HEADER = /^## (D-\d+[a-z]?) — (\d{4}-\d{2}-\d{2}) —/gm;
const INDEX_ENTRY = /^- (D-\d+[a-z]?) — (\d{4}-\d{2}-\d{2}) — (\S.*)$/;

interface Decision {
  id: string;
  date: string;
  timestamp: string;
  text: string;
}

interface IndexEntry {
  id: string;
  date: string;
}

interface ExportResult {
  added: number;
  unchanged: number;
  sourceDirectory: string;
}

class CliFailure extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.exitCode = exitCode;
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function lineNumberAt(text: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (text.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

function timestampFor(date: string, location: string): string {
  const timestamp = `${date}T00:00:00.000Z`;
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== timestamp) {
    throw new CliFailure(`${location}: invalid calendar date ${JSON.stringify(date)}`);
  }
  return timestamp;
}

function readRequiredFile(root: string, name: string): string {
  const path = join(root, name);
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new CliFailure(`Cannot read required ${name}: ${detail}`);
  }
}

function parseDecisions(text: string): Decision[] {
  const matches = [...text.matchAll(DECISION_HEADER)];
  const validOffsets = new Set(matches.map((match) => match.index));

  for (const candidate of text.matchAll(/^## D(?:-|\d)[^\r\n]*$/gm)) {
    if (!validOffsets.has(candidate.index)) {
      throw new CliFailure(
        `${MEMORY_FILE}:${lineNumberAt(text, candidate.index)}: malformed decision header ${JSON.stringify(candidate[0])}`,
      );
    }
  }

  if (matches.length === 0) {
    throw new CliFailure(`${MEMORY_FILE}: no decision headers matched ${DECISION_HEADER.source}`);
  }

  const decisions: Decision[] = [];
  const seen = new Set<string>();
  for (const [index, match] of matches.entries()) {
    const id = match[1];
    const date = match[2];
    if (id === undefined || date === undefined || match.index === undefined) {
      throw new CliFailure(`${MEMORY_FILE}: internal decision parser failure`);
    }
    if (seen.has(id)) {
      throw new CliFailure(`${MEMORY_FILE}:${lineNumberAt(text, match.index)}: duplicate decision ID ${id}`);
    }
    seen.add(id);
    const nextOffset = matches[index + 1]?.index ?? text.length;
    decisions.push({
      id,
      date,
      timestamp: timestampFor(date, `${MEMORY_FILE}:${lineNumberAt(text, match.index)}`),
      text: text.slice(match.index, nextOffset),
    });
  }
  return decisions;
}

function parseIndex(text: string, filename: string): Map<string, IndexEntry> {
  const lines = text.split(/\r?\n/);
  const entryHeadings = lines
    .map((line, index) => (line === "## Entries" ? index : -1))
    .filter((index) => index >= 0);
  if (entryHeadings.length !== 1) {
    throw new CliFailure(`${filename}: expected exactly one "## Entries" heading, found ${entryHeadings.length}`);
  }

  const heading = entryHeadings[0];
  if (heading === undefined) throw new CliFailure(`${filename}: internal index parser failure`);
  const entries = new Map<string, IndexEntry>();
  for (let index = heading + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.startsWith("## ")) break;
    if (line === "") continue;
    const match = INDEX_ENTRY.exec(line);
    if (!match) {
      throw new CliFailure(`${filename}:${index + 1}: malformed index entry ${JSON.stringify(line)}`);
    }
    const id = match[1];
    const date = match[2];
    if (id === undefined || date === undefined) throw new CliFailure(`${filename}: internal index parser failure`);
    if (entries.has(id)) {
      throw new CliFailure(`${filename}:${index + 1}: duplicate decision ID ${id}`);
    }
    timestampFor(date, `${filename}:${index + 1}`);
    entries.set(id, { id, date });
  }
  return entries;
}

function validateIndexes(
  decisions: readonly Decision[],
  lean: ReadonlyMap<string, IndexEntry>,
  archive: ReadonlyMap<string, IndexEntry>,
): void {
  const overlap = [...lean.keys()].filter((id) => archive.has(id)).sort(compareText);
  if (overlap.length > 0) {
    throw new CliFailure(`Lean and archive indexes overlap: ${overlap.join(", ")}`);
  }

  const decisionsById = new Map(decisions.map((decision) => [decision.id, decision]));
  const allIndexEntries = new Map([...lean, ...archive]);
  const missing = [...decisionsById.keys()].filter((id) => !allIndexEntries.has(id)).sort(compareText);
  const unknown = [...allIndexEntries.keys()].filter((id) => !decisionsById.has(id)).sort(compareText);
  if (missing.length > 0 || unknown.length > 0) {
    const details = [
      missing.length > 0 ? `missing from indexes: ${missing.join(", ")}` : undefined,
      unknown.length > 0 ? `not present in ${MEMORY_FILE}: ${unknown.join(", ")}` : undefined,
    ].filter((detail): detail is string => detail !== undefined);
    throw new CliFailure(`Index union does not exactly match decisions (${details.join("; ")})`);
  }

  const wrongDates = [...allIndexEntries.values()]
    .filter((entry) => decisionsById.get(entry.id)?.date !== entry.date)
    .map((entry) => `${entry.id} index=${entry.date} memory=${decisionsById.get(entry.id)?.date}`)
    .sort(compareText);
  if (wrongDates.length > 0) {
    throw new CliFailure(`Index dates do not match ${MEMORY_FILE}: ${wrongDates.join(", ")}`);
  }
}

function jsonlFor(decision: Decision): string {
  const sessionId = `harvey-memory-${decision.id}`;
  const sessionMeta = {
    timestamp: decision.timestamp,
    type: "session_meta",
    payload: {
      id: sessionId,
      cwd: "/Harvey",
    },
  };
  const responseItem = {
    timestamp: decision.timestamp,
    type: "response_item",
    payload: {
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: decision.text }],
    },
  };
  return `${JSON.stringify(sessionMeta)}\n${JSON.stringify(responseItem)}\n`;
}

function ensureDirectory(path: string, label: string): void {
  if (!existsSync(path)) {
    mkdirSync(path);
    return;
  }
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new CliFailure(`${label} must be a real directory: ${path}`);
  }
}

function exportMemory(root: string): ExportResult {
  const decisions = parseDecisions(readRequiredFile(root, MEMORY_FILE));
  const lean = parseIndex(readRequiredFile(root, LEAN_INDEX_FILE), LEAN_INDEX_FILE);
  const archive = parseIndex(readRequiredFile(root, ARCHIVE_INDEX_FILE), ARCHIVE_INDEX_FILE);
  validateIndexes(decisions, lean, archive);

  const adapterDirectory = join(root, ".funes-harvey");
  const sourceDirectory = join(adapterDirectory, "source");
  ensureDirectory(adapterDirectory, ".funes-harvey");
  ensureDirectory(sourceDirectory, "Funes source directory");

  const expected = new Map(
    decisions.map((decision) => [`${decision.id}.jsonl`, { decision, bytes: jsonlFor(decision) }]),
  );
  const existingNames = readEntriesLstatSafe(sourceDirectory).sort((left, right) =>
    compareText(left.name, right.name),
  );
  const existing = new Set<string>();

  for (const entry of existingNames) {
    const generated = expected.get(entry.name);
    if (!generated) {
      const removed = /^(D-\d+[a-z]?)\.jsonl$/.exec(entry.name)?.[1];
      if (removed) {
        throw new CliFailure(
          `Refusing append-only export: generated file for removed decision ${removed} still exists`,
        );
      }
      throw new CliFailure(`Refusing append-only export: unexplained extra in source directory: ${entry.name}`);
    }
    if (!entry.isFile || entry.isSymbolicLink) {
      throw new CliFailure(`Refusing append-only export: historical generated path is not a regular file: ${entry.name}`);
    }
    const actual = readFileSync(join(sourceDirectory, entry.name));
    if (!actual.equals(Buffer.from(generated.bytes, "utf8"))) {
      throw new CliFailure(`Refusing append-only export: historical generated file was modified: ${entry.name}`);
    }
    existing.add(entry.name);
  }

  const additions = [...expected.entries()]
    .filter(([name]) => !existing.has(name))
    .sort(([left], [right]) => compareText(left, right));
  for (const [name, generated] of additions) {
    try {
      writeFileSync(join(sourceDirectory, name), generated.bytes, { encoding: "utf8", flag: "wx" });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new CliFailure(`Could not append generated source ${name}: ${detail}`);
    }
  }

  return { added: additions.length, unchanged: existing.size, sourceDirectory };
}

function sanitizedFunesEnvironment(root: string): NodeJS.ProcessEnv {
  const adapterDirectory = join(root, ".funes-harvey");
  ensureDirectory(adapterDirectory, ".funes-harvey");
  const funesHome = join(adapterDirectory, "funes");
  const hfHome = join(adapterDirectory, "huggingface");
  ensureDirectory(funesHome, "FUNES_HOME");
  ensureDirectory(hfHome, "HF_HOME");

  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(env)) {
    if (name.startsWith("FUNES_")) delete env[name];
  }
  delete env.HF_TOKEN;
  delete env.HUGGING_FACE_HUB_TOKEN;
  delete env.HUGGINGFACE_TOKEN;
  delete env.HF_HUB_CACHE;
  env.FUNES_HOME = funesHome;
  env.HF_HOME = hfHome;
  return env;
}

function funesExecutable(): string {
  if (Object.hasOwn(process.env, "FUNES_BIN")) {
    const override = process.env.FUNES_BIN?.trim();
    if (!override) throw new CliFailure("FUNES_BIN is set but empty");
    return override;
  }
  return "funes";
}

function requireFunesVersion(root: string, executable: string, env: NodeJS.ProcessEnv): void {
  const result = spawnSync(executable, ["--version"], {
    cwd: root,
    encoding: "utf8",
    env,
    shell: false,
  });
  if (result.error) {
    throw new CliFailure(`Could not execute ${JSON.stringify(executable)} --version: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new CliFailure(
      `${JSON.stringify(executable)} --version exited ${result.status ?? `on signal ${result.signal ?? "unknown"}`}`,
    );
  }
  const reported = result.stdout.trim();
  if (reported !== `funes ${REQUIRED_FUNES_VERSION}`) {
    throw new CliFailure(
      `Funes ${REQUIRED_FUNES_VERSION} is required; ${JSON.stringify(executable)} --version reported ${JSON.stringify(reported)}`,
    );
  }
}

function runFunes(root: string, args: readonly string[]): void {
  const executable = funesExecutable();
  const env = sanitizedFunesEnvironment(root);
  requireFunesVersion(root, executable, env);
  const result = spawnSync(executable, [...args], {
    cwd: root,
    env,
    shell: false,
    stdio: "inherit",
  });
  if (result.error) {
    throw new CliFailure(`Could not execute ${JSON.stringify(executable)}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new CliFailure(
      `Funes exited ${result.status ?? `on signal ${result.signal ?? "unknown"}`}`,
      result.status && result.status > 0 ? result.status : 1,
    );
  }
}

function printUsage(): void {
  console.log(
    [
      "Usage:",
      "  pnpm exec tsx tools/funes-memory.ts export",
      "  pnpm exec tsx tools/funes-memory.ts index",
      "  pnpm exec tsx tools/funes-memory.ts recall <query...>",
    ].join("\n"),
  );
}

function main(args: readonly string[]): void {
  const root = resolve(process.cwd());
  const [command, ...rest] = args;
  if (command === "export") {
    if (rest.length > 0) throw new CliFailure("export takes no arguments");
    const result = exportMemory(root);
    console.log(`Funes source export: ${result.added} added, ${result.unchanged} unchanged`);
    return;
  }
  if (command === "index") {
    if (rest.length > 0) throw new CliFailure("index takes no arguments");
    const result = exportMemory(root);
    console.log(`Funes source export: ${result.added} added, ${result.unchanged} unchanged`);
    runFunes(root, ["index", result.sourceDirectory, "--harness", "codex", "--yes", "--no-thinking"]);
    return;
  }
  if (command === "recall") {
    const query = rest.join(" ").trim();
    if (!query) throw new CliFailure("recall requires a non-empty query");
    runFunes(root, ["recall", "--memory", "local", "--half-life", "0", "--", query]);
    return;
  }
  if (command === "help" || command === "--help" || command === "-h") {
    if (rest.length > 0) throw new CliFailure("help takes no arguments");
    printUsage();
    return;
  }
  throw new CliFailure(`Unknown command ${JSON.stringify(command ?? "")}; expected export, index, or recall`);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  const failure = error instanceof CliFailure ? error : new CliFailure(error instanceof Error ? error.message : String(error));
  console.error(`funes-memory: ${failure.message}`);
  process.exitCode = failure.exitCode;
}
