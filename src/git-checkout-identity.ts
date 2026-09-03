import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { statSafe } from "./fs-walk.js";

interface GitCheckoutIdentity {
  repo: string;
  commit: string;
}

function readTrimmed(path: string): string {
  return readFileSync(path, "utf8").trim();
}

function resolveGitDirectory(repoRoot: string): { gitDir: string; commonDir: string } {
  const dotGit = join(repoRoot, ".git");
  let gitDir = dotGit;

  if (!statSafe(dotGit)?.isDirectory()) {
    const match = /^gitdir:\s*(.+)$/i.exec(readTrimmed(dotGit));
    if (!match?.[1]) throw new Error(`${dotGit} is not a Git directory pointer`);
    gitDir = isAbsolute(match[1]) ? match[1] : resolve(repoRoot, match[1]);
  }

  const commonDirFile = join(gitDir, "commondir");
  const commonDir = existsSync(commonDirFile)
    ? resolve(gitDir, readTrimmed(commonDirFile))
    : gitDir;
  return { gitDir, commonDir };
}

function readPackedRef(commonDir: string, ref: string): string | undefined {
  const path = join(commonDir, "packed-refs");
  if (!existsSync(path)) return undefined;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    if (!line || line.startsWith("#") || line.startsWith("^")) continue;
    const separator = line.indexOf(" ");
    if (separator > 0 && line.slice(separator + 1) === ref) return line.slice(0, separator);
  }
  return undefined;
}

function readHeadCommit(gitDir: string, commonDir: string): string {
  const head = readTrimmed(join(gitDir, "HEAD"));
  let commit = head;
  if (head.startsWith("ref:")) {
    const ref = head.slice(4).trim();
    if (!/^refs\/[A-Za-z0-9._/-]+$/.test(ref) || ref.split("/").includes("..")) {
      throw new Error(`unsupported Git HEAD reference: ${ref}`);
    }
    const candidates = [join(gitDir, ref), join(commonDir, ref)];
    const looseRef = candidates.find((path) => existsSync(path));
    commit = looseRef ? readTrimmed(looseRef) : (readPackedRef(commonDir, ref) ?? "");
  }
  if (!/^[0-9a-f]{40}$/i.test(commit)) {
    throw new Error(`cannot resolve an exact 40-character Git HEAD commit from ${gitDir}`);
  }
  return commit.toLowerCase();
}

function readOrigin(commonDir: string, gitDir: string): string {
  const configPath = [join(commonDir, "config"), join(gitDir, "config")].find((path) => existsSync(path));
  if (!configPath) throw new Error(`Git config is missing under ${commonDir}`);

  let inOrigin = false;
  for (const line of readFileSync(configPath, "utf8").split(/\r?\n/)) {
    const section = /^\s*\[([^\]]+)]\s*$/.exec(line);
    if (section) {
      inOrigin = /^remote\s+"origin"$/i.test(section[1]?.trim() ?? "");
      continue;
    }
    if (!inOrigin) continue;
    const url = /^\s*url\s*=\s*(.+?)\s*$/i.exec(line)?.[1];
    if (url) return url;
  }
  throw new Error(`Git remote origin URL is missing from ${configPath}`);
}

/** Read immutable checkout identity without spawning Git or executing target code. */
export function readGitCheckoutIdentity(repoPath: string): GitCheckoutIdentity {
  const repoRoot = resolve(repoPath);
  const { gitDir, commonDir } = resolveGitDirectory(repoRoot);
  return {
    repo: readOrigin(commonDir, gitDir),
    commit: readHeadCommit(gitDir, commonDir),
  };
}
