import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import ts from "typescript";
import { parse as parseYaml } from "yaml";
import { censusDigest, censusGitObject, type EvidenceLocation, type EvidenceVenue } from "./environment-dependency-census-schema.js";

// Only circular outputs are excluded. Census implementation and tests are ordinary inputs.
export const CENSUS_SELF_PATHS = [
  "src/environment-dependency-inventory.json",
  "docs/design/environment-dependency-census.md",
] as const;

export interface CensusFile {
  path: string; bytes: Buffer; text: string | null; format: string;
  gitMode: string; gitOid: string;
  source?: ts.SourceFile; data?: unknown; literalCount: number; literalSha256: string | null;
  limitation: string | null;
}
export interface CensusSnapshot { commit: string; tree: string; commitPayload: string; excludedObjects: { path: string; gitMode: string; gitOid: string }[]; mode: "committed" | "working-tree"; files: CensusFile[] }

function decode(path: string, bytes: Buffer, gitMode = "100644", gitOid = censusGitObject("blob", bytes)): CensusFile {
  const result: CensusFile = { path, bytes, gitMode, gitOid, text: null, format: "opaque", literalCount: 0, literalSha256: null, limitation: null };
  let decoded = bytes;
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    try { decoded = gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 }); result.format = "gzip"; }
    catch { result.limitation = "Gzip could not be decoded within 128 MiB. Original bytes remain in the denominator; contents are unresolved."; return result; }
  }
  try { result.text = new TextDecoder("utf-8", { fatal: true }).decode(decoded); }
  catch { result.limitation = "Non-UTF-8 content is retained by byte digest; no semantic or environment identity claim is made."; return result; }
  if (result.text.includes("\0")) { result.text = null; result.limitation = "Binary content is retained by byte digest; environment dependencies remain unresolved."; return result; }
  const prefix = result.format === "gzip" ? "gzip/" : "";
  result.format = `${prefix}text`;
  // Content admits JSON even in .txt, extensionless files, or an unfamiliar directory.
  if (result.text.trimStart().startsWith("[") || result.text.trimStart().startsWith("{")) {
    try { result.data = JSON.parse(result.text); result.format = `${prefix}json`; return result; } catch { /* A source array or invalid JSON remains an examined text candidate. */ }
  }
  if (/\.(?:[cm]?[jt]sx?)(?:\.txt)?$/.test(path)) {
    result.source = ts.createSourceFile(path.replace(/\.txt$/, ""), result.text, ts.ScriptTarget.Latest, true, /[jt]sx(?:\.txt)?$/.test(path) ? ts.ScriptKind.TSX : /[cm]?ts(?:\.txt)?$/.test(path) ? ts.ScriptKind.TS : ts.ScriptKind.JS);
    const literals: string[] = [];
    const visit = (node: ts.Node): void => {
      // Include ordinary strings/numbers, not merely property names like "baseline".
      // A hidden measurement therefore changes the receipt without a vocabulary hit.
      if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) literals.push(node.getText(result.source));
      ts.forEachChild(node, visit);
    };
    visit(result.source);
    result.literalCount = literals.length;
    result.literalSha256 = censusDigest(JSON.stringify(literals));
    result.format = "source";
  } else if (/\.ya?ml$/.test(path) || /^(?:name|jobs|schema|version|services):/m.test(result.text)) {
    try { result.data = parseYaml(result.text, { maxAliasCount: 100 }); result.format = `${prefix}yaml`; }
    catch { result.limitation = "Structured-looking text did not decode as YAML; its complete bytes remain an unresolved candidate."; }
  }
  return result;
}

/** Read Git objects, never execute source or follow a committed symlink to host files. */
export function readCensusSnapshot(root: string, ref: string | undefined, workingTree = false): CensusSnapshot {
  const git = (args: string[], input?: string): Buffer => execFileSync("git", args, { cwd: root, input, maxBuffer: 512 * 1024 * 1024 });
  const commit = git(["rev-parse", "--verify", `${ref ?? "HEAD"}^{commit}`]).toString().trim();
  const tree = git(["rev-parse", "--verify", `${commit}^{tree}`]).toString().trim();
  const commitPayload = git(["cat-file", "commit", commit]).toString("base64");
  if (!/^[a-f0-9]{40}$/.test(commit) || !/^[a-f0-9]{40}$/.test(tree)) throw new Error("census requires exact Git object identities");
  const entries = git(["ls-tree", "--full-tree", "-r", "-z", commit]).toString().split("\0").filter(Boolean).map((entry) => {
    const tab = entry.indexOf("\t");
    const [mode, kind, oid] = entry.slice(0, tab).split(" ");
    return { path: entry.slice(tab + 1), mode, kind, oid: oid! };
  });
  const files: CensusFile[] = [];
  const self = new Set<string>(CENSUS_SELF_PATHS);
  if (workingTree) {
    // Include indexed removals (detected by the comparison), tracked modifications, and
    // unignored additions. This makes the local gate useful before a commit, too.
    const paths = [...new Set(git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).toString().split("\0").filter(Boolean))].sort();
    for (const path of paths) {
      if (self.has(path)) continue;
      let stat;
      try { stat = lstatSync(join(root, path)); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") continue; throw error; }
      if (stat.isSymbolicLink()) {
        files.push({ ...decode(path, Buffer.from(readlinkSync(join(root, path))), "120000"), text: null, format: "symlink", limitation: "Committed symlink bytes are retained; host destination is not followed." });
      } else if (!stat.isFile()) {
        const entry = entries.find((e) => e.path === path);
        if (entry?.kind !== "commit") throw new Error(`unregistered non-file Git entry ${path}`);
        files.push({ ...decode(path, Buffer.from(`${entry.kind} ${entry.oid}`), "160000", entry.oid), text: null, format: "gitlink", limitation: "Gitlink contents are outside this committed tree; the target identity is retained, dependency contents unresolved." });
      } else files.push(decode(path, readFileSync(join(root, path)), stat.mode & 0o111 ? "100755" : "100644"));
    }
  } else {
    const blobs = entries.filter((e) => e.kind === "blob" && !self.has(e.path));
    const batch = blobs.length ? git(["cat-file", "--batch"], blobs.map((e) => e.oid).join("\n") + "\n") : Buffer.alloc(0);
    let offset = 0;
    for (const entry of blobs) {
      const end = batch.indexOf(10, offset);
      const header = batch.subarray(offset, end).toString().split(" ");
      const size = Number(header[2]);
      if (header[0] !== entry.oid || header[1] !== "blob" || !Number.isSafeInteger(size) || size < 0) throw new Error(`invalid Git blob receipt ${entry.path}`);
      const bytes = batch.subarray(end + 1, end + 1 + size);
      if (bytes.length !== size) throw new Error(`truncated Git blob ${entry.path}`);
      offset = end + size + 2;
      const file = decode(entry.path, bytes, entry.mode, entry.oid);
      if (entry.mode === "120000") { file.text = null; file.format = "symlink"; file.limitation = "Committed symlink bytes are retained; host destination is not followed."; }
      files.push(file);
    }
    for (const entry of entries.filter((e) => e.kind !== "blob" && !self.has(e.path))) files.push({ ...decode(entry.path, Buffer.from(`${entry.kind} ${entry.oid}`), "160000", entry.oid), text: null, format: "gitlink", limitation: "Gitlink contents are outside this committed tree; the target identity is retained, dependency contents unresolved." });
  }
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const excludedObjects = entries.filter((e) => self.has(e.path)).map((e) => ({ path: e.path, gitMode: e.mode!, gitOid: e.oid }));
  return { commit, tree, commitPayload, excludedObjects, mode: workingTree ? "working-tree" : "committed", files };
}

export function censusLocation(file: CensusFile, anchor: string, needle?: string): EvidenceLocation {
  const offset = needle ? (file.text ?? "").indexOf(needle) : 0;
  return { path: file.path, anchor, line: offset < 0 ? 1 : (file.text ?? "").slice(0, offset).split("\n").length };
}

export function discoverCensusVenue(file: CensusFile): EvidenceVenue {
  const data = file.data && typeof file.data === "object" && !Array.isArray(file.data) ? file.data as Record<string, unknown> : null;
  const kind: EvidenceVenue["kind"] = file.text === null ? "opaque" : data?.jobs || data?.runs ? "workflow" : file.source ? "source" : data || Array.isArray(file.data) ? "structured-data" : "document";
  return { id: file.path, path: file.path, kind, format: file.format, bytes: file.bytes.length, sha256: censusDigest(file.bytes), gitMode: file.gitMode, gitOid: file.gitOid, literalCount: file.literalCount, literalSha256: file.literalSha256,
    owner: "#1906 discovery; #1909 environment classification",
    disposition: kind === "opaque" ? "opaque-unresolved" : "conservative-candidate",
    reason: file.limitation ?? "Complete committed bytes are retained as a conservative candidate. Static discovery does not prove that every literal is evidence or that an absent identity is safe; authoritative adapters and unresolved rows distinguish those claims.",
  };
}
