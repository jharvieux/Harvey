// Intent (#1231/#1232): the workspace member set must come from the DECLARED globs. The failure
// this guards is not "we found too few manifests" but the opposite — the naive alternative, a
// filesystem sweep for every package.json outside node_modules, pulls in examples/ and standalone
// fixture roots and reports their deliberately-pinned vulnerable dependencies as the application's
// own. Every assertion below is about which manifests are IN, and which stay out.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectWorkspaceManifests } from "./workspaces.js";

describe("collectWorkspaceManifests", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-workspaces-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const manifest = (rel: string, body: object): void => {
    mkdirSync(join(dir, rel), { recursive: true });
    writeFileSync(join(dir, rel, "package.json"), JSON.stringify(body));
  };
  const root = (body: object): void => writeFileSync(join(dir, "package.json"), JSON.stringify(body));

  it("reads only the root manifest for a single-package repo", () => {
    root({ name: "app", dependencies: { react: "^18.2.0" } });
    const scope = collectWorkspaceManifests(dir);
    expect(scope.manifests.map((m) => m.label)).toEqual(["package.json"]);
    expect(scope.source).toBe("no workspace globs declared");
  });

  it("resolves pnpm-workspace.yaml globs, including a nested ** member", () => {
    root({ name: "monorepo" });
    writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n  - 'packages/**'\n");
    manifest("apps/web", { name: "web", dependencies: { next: "^14.2.5" } });
    manifest("packages/features/auth", { name: "auth", dependencies: { zod: "^3.22.0" } });
    const scope = collectWorkspaceManifests(dir);
    expect(scope.manifests.map((m) => m.label).sort()).toEqual([
      join("apps", "web", "package.json"),
      join("packages", "features", "auth", "package.json"),
      "package.json",
    ].sort());
    expect(scope.source).toBe("pnpm-workspace.yaml");
  });

  it("resolves package.json#workspaces in both the array and the { packages } shape", () => {
    root({ name: "monorepo", workspaces: { packages: ["apps/*"] } });
    manifest("apps/api", { name: "api" });
    expect(collectWorkspaceManifests(dir).manifests).toHaveLength(2);
    root({ name: "monorepo", workspaces: ["apps/*"] });
    const scope = collectWorkspaceManifests(dir);
    expect(scope.manifests).toHaveLength(2);
    expect(scope.source).toBe("package.json#workspaces");
  });

  // THE trap this module exists to avoid. `examples/` and a standalone fixture root are not
  // workspace members, and their manifests pin versions chosen to be wrong.
  it("leaves an unlisted examples/ or fixture manifest out of the member set", () => {
    root({ name: "monorepo", workspaces: ["apps/*"] });
    manifest("apps/web", { name: "web" });
    manifest("examples/demo", { name: "demo", dependencies: { minimist: "1.2.5" } });
    manifest("fixtures/legacy-app", { name: "legacy", dependencies: { "flatmap-stream": "0.1.1" } });
    const labels = collectWorkspaceManifests(dir).manifests.map((m) => m.label);
    expect(labels).toHaveLength(2);
    expect(labels.join(" ")).not.toContain("examples");
    expect(labels.join(" ")).not.toContain("fixtures");
  });

  // expandGlob has no notion of "!", so a negated entry would otherwise be walked as a literal
  // directory named "!examples" — a silent no-op that keeps the excluded member in scope.
  it("honours a negated glob rather than walking it as a literal directory", () => {
    root({ name: "monorepo" });
    writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages:\n  - 'packages/*'\n  - '!packages/scratch'\n");
    manifest("packages/ui", { name: "ui" });
    manifest("packages/scratch", { name: "scratch" });
    const labels = collectWorkspaceManifests(dir).manifests.map((m) => m.label);
    expect(labels).toContain(join("packages", "ui", "package.json"));
    expect(labels).not.toContain(join("packages", "scratch", "package.json"));
  });

  it("names a glob that matched nothing instead of degrading silently to the root", () => {
    root({ name: "monorepo", workspaces: ["apps/*", "services/*"] });
    manifest("apps/web", { name: "web" });
    const scope = collectWorkspaceManifests(dir);
    expect(scope.unresolvedGlobs).toEqual(["services/*"]);
  });

  it("counts a manifest it could not parse rather than treating it as dependency-free", () => {
    root({ name: "monorepo", workspaces: ["apps/*"] });
    mkdirSync(join(dir, "apps", "broken"), { recursive: true });
    writeFileSync(join(dir, "apps", "broken", "package.json"), "{ not json");
    const scope = collectWorkspaceManifests(dir);
    expect(scope.manifests.map((m) => m.label)).toEqual(["package.json"]);
    expect(scope.unreadable).toEqual([join("apps", "broken", "package.json")]);
  });
});
