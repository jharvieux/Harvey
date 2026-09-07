#!/usr/bin/env node

// Codex PreToolUse guard for the one edit that must never become last-write-wins:
// rewriting a prior MEMORY.md decision. It intentionally matches apply_patch only;
// the repository validator remains the backstop for other edit paths and Git merges.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const HEADER = /^## (D-(\d{3,})) — (\d{4}-\d{2}-\d{2}) — (\S(?:.*\S)?)$/;

function block(reason) {
  process.stderr.write(`BLOCKED: ${reason}\n`);
  process.exit(2);
}

function parsePatch(command) {
  if (typeof command !== "string") throw new Error("tool_input.command must be a string");
  const lines = command.replaceAll("\r\n", "\n").trimEnd().split("\n");
  if (lines[0] !== "*** Begin Patch" || lines.at(-1) !== "*** End Patch") {
    throw new Error("missing Begin Patch or End Patch marker");
  }

  const sections = [];
  let section;
  let hunk;
  for (const line of lines.slice(1, -1)) {
    const file = line.match(/^\*\*\* (Add|Delete|Update) File: (.+)$/);
    if (file) {
      section = { operation: file[1], path: file[2].trim(), moveTo: null, hunks: [] };
      if (!section.path) throw new Error("empty file path");
      sections.push(section);
      hunk = undefined;
      continue;
    }
    const move = line.match(/^\*\*\* Move to: (.+)$/);
    if (move) {
      if (!section || section.operation !== "Update" || section.moveTo) throw new Error("invalid Move to marker");
      section.moveTo = move[1].trim();
      if (!section.moveTo) throw new Error("empty move target");
      continue;
    }
    if (line.startsWith("@@")) {
      if (!section) throw new Error("hunk before file header");
      hunk = [];
      section.hunks.push(hunk);
      continue;
    }
    if (!section) {
      if (line.trim()) throw new Error("content before first file header");
      continue;
    }
    if (!hunk) {
      // Add/Delete file bodies have no @@ marker. They cannot be valid MEMORY.md prepends,
      // but retaining them lets unrelated patches pass through this narrow guard.
      hunk = [];
      section.hunks.push(hunk);
    }
    hunk.push(line);
  }
  if (sections.length === 0) throw new Error("patch contains no file sections");
  return sections;
}

function isRepoMemoryPath(repoRoot, path) {
  const rel = relative(repoRoot, resolve(repoRoot, path));
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) && rel.toLowerCase() === "memory.md";
}

function sameLines(actual, expected) {
  return actual.length === expected.length && actual.every((line, index) => line === expected[index]);
}

function parseAddedEntries(lines) {
  if (lines.length < 2 || lines.at(-1) !== "") return null;
  const headerIndexes = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (HEADER.test(lines[index])) headerIndexes.push(index);
  }
  if (headerIndexes.length === 0 || headerIndexes[0] !== 0) return null;

  const entries = [];
  for (let index = 0; index < headerIndexes.length; index += 1) {
    const start = headerIndexes[index];
    const end = headerIndexes[index + 1] ?? lines.length;
    const block = lines.slice(start, end).join("\n");
    const match = lines[start].match(HEADER);
    if (!match || !block.includes("\n\n**Decision.** ") || !block.includes("\n\n**Why.**\n- ")) return null;
    if (!block.includes("\n\n**Rejected.**\n- ") || !block.includes("\n\n**Related artifacts.** ")) return null;
    if (!/\n\n---\n*$/.test(block)) return null;
    entries.push({ id: match[1], number: Number(match[2]) });
  }
  return entries;
}

function isPurePrepend(section, current) {
  if (section.operation !== "Update" || section.moveTo || section.hunks.length !== 1) return false;
  const body = section.hunks[0];
  if (body.some((line) => line.length === 0 || ![" ", "+", "-"].includes(line[0]))) return false;
  if (body.some((line) => line.startsWith("-") || line === "*** End of File")) return false;

  const addedIndexes = body.flatMap((line, index) => (line.startsWith("+") ? [index] : []));
  if (addedIndexes.length === 0) return false;
  const firstAdded = addedIndexes[0];
  const lastAdded = addedIndexes.at(-1);
  if (lastAdded - firstAdded + 1 !== addedIndexes.length) return false;

  const before = body.slice(0, firstAdded).map((line) => line.slice(1));
  const addedLines = body.slice(firstAdded, lastAdded + 1).map((line) => line.slice(1));
  const after = body.slice(lastAdded + 1).map((line) => line.slice(1));
  if (before.length === 0 || after.length === 0) return false;
  if (body.slice(0, firstAdded).some((line) => !line.startsWith(" "))) return false;
  if (body.slice(lastAdded + 1).some((line) => !line.startsWith(" "))) return false;

  const currentLines = current.replaceAll("\r\n", "\n").split("\n");
  const firstEntry = currentLines.findIndex((line) => HEADER.test(line));
  if (firstEntry < 0 || before.length > firstEntry) return false;
  if (!sameLines(currentLines.slice(firstEntry - before.length, firstEntry), before)) return false;
  if (!sameLines(currentLines.slice(firstEntry, firstEntry + after.length), after)) return false;

  const added = parseAddedEntries(addedLines);
  if (!added) return false;
  const existingNumbers = currentLines.flatMap((line) => {
    const match = line.match(HEADER);
    return match ? [Number(match[2])] : [];
  });
  const maximum = existingNumbers.length === 0 ? 0 : Math.max(...existingNumbers);
  const expected = added.map((_, index) => maximum + added.length - index);
  return added.every((entry, index) => entry.number === expected[index]);
}

function memoryAt(repoRoot, ref) {
  try {
    const paths = execFileSync("git", ["ls-tree", "--name-only", ref, "--", "MEMORY.md"], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    if (!paths) return { known: true, text: null };
    const text = execFileSync("git", ["show", `${ref}:MEMORY.md`], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { known: true, text };
  } catch {
    return { known: false, text: null };
  }
}

function isBranchLocalRenumber(section, current, repoRoot) {
  if (section.operation !== "Update" || section.moveTo || section.hunks.length !== 1) return false;
  const body = section.hunks[0];
  if (body.some((line) => line.length === 0 || ![" ", "+", "-"].includes(line[0]))) return false;
  const deleted = body.filter((line) => line.startsWith("-")).map((line) => line.slice(1));
  const added = body.filter((line) => line.startsWith("+")).map((line) => line.slice(1));
  if (deleted.length === 0 || added.length === 0) return false;
  const oldText = deleted.join("\n");
  const newText = added.join("\n");
  const oldIds = [...new Set(oldText.match(/D-\d{3,}/g) ?? [])];
  const newIds = [...new Set(newText.match(/D-\d{3,}/g) ?? [])];
  if (oldIds.length !== 1 || newIds.length !== 1 || oldIds[0] === newIds[0]) return false;
  if (oldText.replaceAll(oldIds[0], newIds[0]) !== newText) return false;
  const currentHeader = new RegExp(`^## ${oldIds[0]}\\b`, "m");
  const headerMatch = current.match(currentHeader);
  const snippetOffset = current.indexOf(oldText);
  if (!headerMatch || snippetOffset < 0 || headerMatch.index === undefined) return false;
  const nextHeader = current.slice(headerMatch.index + headerMatch[0].length).search(/^## D-\d{3,}\b/m);
  const entryEnd = nextHeader < 0 ? current.length : headerMatch.index + headerMatch[0].length + nextHeader;
  if (snippetOffset < headerMatch.index || snippetOffset >= entryEnd) return false;
  const newHeader = new RegExp(`^## ${newIds[0]}\\b`, "m");
  if (newHeader.test(current)) return false;
  const targetRef = process.env.HARVEY_MEMORY_BASE_REF ?? "origin/main";
  let mergeBase;
  try {
    mergeBase = execFileSync("git", ["merge-base", "HEAD", targetRef], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return false;
  }
  const ancestor = memoryAt(repoRoot, mergeBase);
  if (!ancestor.known) return false;
  return ancestor.text === null || !currentHeader.test(ancestor.text);
}

let input;
try {
  input = JSON.parse(readFileSync(0, "utf8"));
} catch (error) {
  block(`memory guard could not parse hook input (${error.message}); refusing the edit fail-closed.`);
}

if (input?.tool_name !== "apply_patch") process.exit(0);

let sections;
try {
  sections = parsePatch(input?.tool_input?.command);
} catch (error) {
  block(`memory guard could not parse apply_patch input (${error.message}); refusing the edit fail-closed.`);
}

const repoRoot = resolve(process.env.HARVEY_REPO_ROOT ?? input?.cwd ?? process.cwd());
const touching = sections.filter(
  (section) => isRepoMemoryPath(repoRoot, section.path) || (section.moveTo && isRepoMemoryPath(repoRoot, section.moveTo)),
);
if (touching.length === 0) process.exit(0);
if (touching.length !== 1) block("one apply_patch call contains multiple MEMORY.md operations.");

let current;
try {
  current = readFileSync(resolve(repoRoot, "MEMORY.md"), "utf8");
} catch (error) {
  block(`MEMORY.md could not be read (${error.message}); prior history cannot be verified.`);
}

const section = touching[0];
if (!isPurePrepend(section, current) && !isBranchLocalRenumber(section, current, repoRoot)) {
  block(
    "MEMORY.md prior history is immutable. Use the memory-entry skill to insert complete new entry blocks at the log boundary; only a pure branch-local D-number renumber is otherwise allowed.",
  );
}

process.exit(0);
