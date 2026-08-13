import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decideCorpusRelevance, discoverCorpusClosure, type CorpusChangedPath } from "../scan/corpus-relevance.js";

const args = process.argv.slice(2);
const value = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const repo = resolve(value("--repo") ?? process.cwd());
const baseRef = value("--base");
const headRef = value("--head") ?? "HEAD";
const out = value("--out");
const githubOutput = value("--github-output");
if (!baseRef || !out) {
  console.error("usage: corpus-relevance --base <ref> [--head <ref>] --out <receipt.json> [--github-output <path>]");
  process.exit(2);
}

const materialize = (ref: string): string => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-"));
  const archive = join(dir, "revision.tar");
  execFileSync("git", ["archive", "--format=tar", `--output=${archive}`, ref], { cwd: repo, stdio: "inherit" });
  execFileSync("tar", ["-xf", archive, "-C", dir], { cwd: repo, stdio: "inherit" });
  rmSync(archive, { force: true });
  return dir;
};

const changedPaths = (): CorpusChangedPath[] => {
  const raw = execFileSync("git", ["diff", "--name-status", "-z", "--find-renames", baseRef, headRef], { cwd: repo });
  const fields = raw.toString("utf8").split("\0").filter(Boolean);
  const changed: CorpusChangedPath[] = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++]!;
    if (status.startsWith("R") || status.startsWith("C")) {
      const oldPath = fields[index++]!;
      const path = fields[index++]!;
      changed.push({ status, oldPath, path });
    } else {
      changed.push({ status, path: fields[index++]! });
    }
  }
  return changed;
};

const baseDir = materialize(baseRef);
const headDir = materialize(headRef);
try {
  const decision = decideCorpusRelevance(
    discoverCorpusClosure(baseDir, execFileSync("git", ["rev-parse", baseRef], { cwd: repo, encoding: "utf8" }).trim()),
    discoverCorpusClosure(headDir, execFileSync("git", ["rev-parse", headRef], { cwd: repo, encoding: "utf8" }).trim()),
    changedPaths(),
  );
  writeFileSync(out, `${JSON.stringify(decision, null, 2)}\n`);
  console.error(`CORPUS RELEVANCE ${decision.verdict.toUpperCase()}: ${decision.reasons.join("; ")}`);
  if (githubOutput) {
    appendFileSync(githubOutput, `relevant=${decision.relevant}\nverdict=${decision.verdict}\nreceipt=${out}\n`);
  }
} finally {
  rmSync(baseDir, { recursive: true, force: true });
  rmSync(headDir, { recursive: true, force: true });
}
