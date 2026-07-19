// #607: on a workspace monorepo, node_modules/<pkg> is a symlink to the target's own packages/*
// source. A wholesale node_modules symlink resolves those workspace packages back to the ORIGINAL
// (unstubbed) source, so a stub applied to packages/foo is bypassed by a cross-package import.
// mirrorNodeModules must re-point workspace-package symlinks at the COPY instead — these tests
// prove the re-pointed link resolves inside the copy (not the original), while ordinary
// third-party entries still resolve to the original install.

import { cpSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mirrorNodeModules } from "./stub-worktree.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const EXCLUDED = /^(node_modules|\.next|\.git|dist|build|coverage|out|reports|stryker-tmp)$/;

// Builds a target monorepo with two workspace packages symlinked into node_modules (one under an
// @scope dir, one top-level) plus a third-party real-dir package, then a copy that mirrors the
// tree with node_modules excluded — exactly what src/cli/mutation-scan.ts --stub-check produces.
function buildMonorepo(): { target: string; copy: string } {
  const target = mkdtempSync(join(tmpdir(), "harvey-ws-target-"));
  dirs.push(target);
  for (const pkg of ["foo", "bar", "baz"]) {
    mkdirSync(join(target, "packages", pkg), { recursive: true });
    writeFileSync(join(target, "packages", pkg, "index.js"), `module.exports = "${pkg}";\n`);
  }
  // foo ships its own (non-hoisted) node_modules — mirrorNodeModules must relink it into the copy.
  mkdirSync(join(target, "packages", "foo", "node_modules", "left-pad"), { recursive: true });
  writeFileSync(join(target, "packages", "foo", "node_modules", "left-pad", "index.js"), "");

  mkdirSync(join(target, "node_modules", "@scope"), { recursive: true });
  symlinkSync(join(target, "packages", "foo"), join(target, "node_modules", "@scope", "foo"), "dir");
  symlinkSync(join(target, "packages", "bar"), join(target, "node_modules", "bar"), "dir");
  symlinkSync(join(target, "packages", "baz"), join(target, "node_modules", "baz"), "dir");
  // a third-party real-dir package — must keep resolving to the original install
  mkdirSync(join(target, "node_modules", "lodash"), { recursive: true });
  writeFileSync(join(target, "node_modules", "lodash", "index.js"), "");

  const copy = mkdtempSync(join(tmpdir(), "harvey-ws-copy-"));
  dirs.push(copy);
  cpSync(target, copy, {
    recursive: true,
    filter: (src) => !(EXCLUDED.test(basename(src)) && statSync(src).isDirectory()),
  });
  return { target, copy };
}

describe("mirrorNodeModules (#607)", () => {
  it("re-points workspace-package symlinks (scoped and top-level) at the COPY, not the original source", () => {
    const { target, copy } = buildMonorepo();
    const mirror = mirrorNodeModules(target, copy);

    // The scoped and top-level workspace packages now resolve INSIDE the copy — a stub written to
    // copy/packages/foo is what a cross-package `require("@scope/foo")` sees.
    expect(realpathSync(join(copy, "node_modules", "@scope", "foo"))).toBe(realpathSync(join(copy, "packages", "foo")));
    expect(realpathSync(join(copy, "node_modules", "bar"))).toBe(realpathSync(join(copy, "packages", "bar")));
    // ...and specifically NOT back at the original (the pre-#607 wholesale-symlink behavior).
    expect(realpathSync(join(copy, "node_modules", "@scope", "foo"))).not.toBe(realpathSync(join(target, "packages", "foo")));

    expect(mirror.repointed).toContain("@scope/foo");
    expect(mirror.repointed).toContain("bar");
    expect(mirror.unresolvedWorkspacePkgs).toHaveLength(0);
  });

  it("keeps ordinary third-party packages resolving to the original install", () => {
    const { target, copy } = buildMonorepo();
    mirrorNodeModules(target, copy);
    expect(realpathSync(join(copy, "node_modules", "lodash"))).toBe(realpathSync(join(target, "node_modules", "lodash")));
  });

  it("relinks a workspace package's own node_modules so its non-hoisted deps still resolve", () => {
    const { target, copy } = buildMonorepo();
    mirrorNodeModules(target, copy);
    expect(realpathSync(join(copy, "packages", "foo", "node_modules", "left-pad"))).toBe(
      realpathSync(join(target, "packages", "foo", "node_modules", "left-pad")),
    );
  });

  it("discloses (never silently drops) a workspace package whose source is not in the copy", () => {
    const { target, copy } = buildMonorepo();
    // Simulate the source having been excluded from the copy — the symlink must fall back to the
    // original AND be reported, not silently point at stale source with no disclosure.
    rmSync(join(copy, "packages", "baz"), { recursive: true, force: true });
    const mirror = mirrorNodeModules(target, copy);
    expect(mirror.unresolvedWorkspacePkgs).toContain("baz");
    expect(realpathSync(join(copy, "node_modules", "baz"))).toBe(realpathSync(join(target, "packages", "baz")));
  });
});
