import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runOsvScanner } from "../scan/dependencies.js";
import { loadCorpusAdvisorySnapshot, type CorpusAdvisorySnapshotEntry, type CorpusAdvisorySnapshotManifest } from "../corpus-advisory-snapshot.js";

const PROPOSIT = {
  slug: "proposit",
  repo: "JakeLeoDev__proposit",
  commit: "82838cef3606a176c4bca0af0587c5ea6b08d3a0",
};

describe("corpus-advisory-snapshot CLI target selection", () => {
  const scratches: string[] = [];
  afterEach(() => scratches.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("refreshes one target without relabelling an untouched target's capture epoch", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-advisory-cli-"));
    scratches.push(root);
    const out = join(root, "out");
    const cache = join(root, "cache");
    const bin = join(root, "bin");
    mkdirSync(out, { recursive: true });
    const cached = join(cache, PROPOSIT.repo);
    mkdirSync(cached, { recursive: true });
    execFileSync("git", ["init", "-q", cached]);
    mkdirSync(bin);
    writeFileSync(join(cache, PROPOSIT.repo, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/fixture": { version: "1.0.0" } } }));

    execFileSync("git", ["-C", cached, "add", "."]);
    execFileSync("git", ["-C", cached, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "Fixture"]);
    const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
    const oldBytes = gzipSync(JSON.stringify({ schema: 1, ...runOsvScanner(out) }));
    const oldEntry = (file: string, targetCommit: string): CorpusAdvisorySnapshotEntry => ({
      file,
      sha256: createHash("sha256").update(oldBytes).digest("hex"),
      targetCommit,
      capturedAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-08-08T00:00:00.000Z",
      osvScannerVersion: "osv-scanner version: 2.3.8",
    });
    writeFileSync(join(out, "proposit.osv.json.gz"), oldBytes);
    writeFileSync(join(out, "untouched.osv.json.gz"), oldBytes);
    const prior: CorpusAdvisorySnapshotManifest = {
      schema: 2,
      targets: {
        proposit: oldEntry("proposit.osv.json.gz", PROPOSIT.commit),
        untouched: oldEntry("untouched.osv.json.gz", "untouched-commit"),
      },
    };
    writeFileSync(join(out, "manifest.json"), JSON.stringify(prior));

    writeFileSync(
      join(bin, "git"),
      `#!/bin/sh\nif [ "$3" = "rev-parse" ] && [ "$4" = "HEAD" ]; then echo ${PROPOSIT.commit}; exit 0; fi\nif [ "$3" = "rev-parse" ] && [ "$4" = "${PROPOSIT.commit}^{tree}" ]; then exec ${realGit} "$1" "$2" rev-parse 'HEAD^{tree}'; fi\nif [ "$3" = "rev-list" ]; then echo ${PROPOSIT.commit}; exit 0; fi\nif [ "$3" = "diff" ] || [ "$3" = "fetch" ]; then exit 0; fi\nexec ${realGit} "$@"\n`,
      { mode: 0o755 },
    );
    writeFileSync(
      join(bin, "osv-scanner"),
      '#!/bin/sh\nif [ "$1" = "--version" ]; then printf "osv-scanner version: 2.3.8\\nosv-scalibr version: 0.4.5\\n"; exit 0; fi\nprintf \'{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"fixture","version":"1.0.0","ecosystem":"npm"}}]}]}\\n\'\n',
      { mode: 0o755 },
    );

    execFileSync(
      process.execPath,
      ["--import", "tsx", "src/cli/corpus-advisory-snapshot.ts", "--out", out, "--target", PROPOSIT.slug],
      {
        cwd: process.cwd(),
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_CORPUS_CACHE_DIR: cache },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const refreshed = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as CorpusAdvisorySnapshotManifest;
    expect(refreshed.schema).toBe(2);
    expect(refreshed.targets.proposit?.capturedAt).not.toBe(prior.targets.proposit?.capturedAt);
    expect(refreshed.targets.untouched).toEqual(prior.targets.untouched);
    expect(loadCorpusAdvisorySnapshot("proposit", PROPOSIT.commit, { dir: out }).capturedAt).toBe(refreshed.targets.proposit?.capturedAt);
    expect(() => loadCorpusAdvisorySnapshot("untouched", "untouched-commit", { dir: out, now: new Date("2026-08-09") })).toThrow(
      "for untouched expired at 2026-08-08T00:00:00.000Z",
    );
  });
});
