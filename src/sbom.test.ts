import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSbom, collectDependencies, licenseScope, parsePackageLock, parsePnpmLock, parseYarnLock } from "./sbom.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the BOM is emitted as plain JSON; tests read it as a consumer would.
const bomOf = (dir: string): any => buildSbom(dir, { targetName: "t", timestamp: "2026-07-23T00:00:00.000Z" }).bom;
const inventory = ({ components, unmatched }: ReturnType<typeof parsePackageLock>) => ({ components, unmatched });

describe("lockfile parsing", () => {
  it("reads resolved versions, the dev flag, and (#1079) the license and integrity hash from package-lock v2/v3", () => {
    const text = JSON.stringify({
      packages: {
        "": { version: "1.0.0" }, // the root project is not a component of itself
        "node_modules/axios": { version: "1.7.2", license: "MIT", integrity: "sha512-AAAA" },
        "node_modules/vitest": { version: "3.2.6", dev: true },
        "node_modules/@next/env": { version: "14.2.35" },
        "node_modules/foo/node_modules/axios": { version: "0.21.1" }, // a nested duplicate is its own component
      },
    });
    expect(inventory(parsePackageLock(text))).toEqual({
      components: [
        { name: "axios", version: "1.7.2", license: "MIT", integrity: "sha512-AAAA" },
        { name: "vitest", version: "3.2.6", dev: true },
        { name: "@next/env", version: "14.2.35" },
        { name: "axios", version: "0.21.1" },
      ],
      unmatched: 0,
    });
  });

  it("normalizes deprecated package-lock license objects without leaking non-strings", () => {
    const text = JSON.stringify({
      packages: {
        "node_modules/legacy": { version: "1.0.0", license: { type: " MIT ", url: "https://example.invalid/license" } },
        "node_modules/malformed": { version: "2.0.0", license: { url: "https://example.invalid/unknown" } },
      },
    });
    expect(inventory(parsePackageLock(text))).toEqual({
      components: [
        { name: "legacy", version: "1.0.0", license: "MIT" },
        { name: "malformed", version: "2.0.0" },
      ],
      unmatched: 0,
    });
  });

  it("falls back to the v1 nested `dependencies` tree", () => {
    const text = JSON.stringify({ dependencies: { axios: { version: "1.7.2", dependencies: { follow: { version: "1.15.4" } } } } });
    expect(inventory(parsePackageLock(text))).toEqual({
      components: [
        { name: "axios", version: "1.7.2" },
        { name: "follow", version: "1.15.4" },
      ],
      unmatched: 0,
    });
  });

  it("reads every pnpm key shape across lockfile versions, and the resolution integrity", () => {
    const text = [
      "lockfileVersion: '9.0'",
      "packages:",
      "",
      "  '@babel/core@7.29.7':",
      "    resolution: {integrity: sha512-x==}",
      "  /braces@2.3.2:",
      "  /minimist/1.2.0:",
      "  'react@18.2.0(typescript@5.9.3)':",
      "",
      "snapshots:",
      "  'should-not-be-read@9.9.9':",
    ].join("\n");
    expect(inventory(parsePnpmLock(text))).toEqual({
      components: [
        { name: "@babel/core", version: "7.29.7", integrity: "sha512-x==" },
        { name: "braces", version: "2.3.2" },
        { name: "minimist", version: "1.2.0" },
        { name: "react", version: "18.2.0" },
      ],
      unmatched: 0,
    });
  });

  it("reads both yarn v1 and Berry entries", () => {
    const v1 = ['braces@^2.3.1:', '  version "2.3.2"', '', '"@babel/core@^7.0.0":', '  version "7.29.7"'].join("\n");
    expect(inventory(parseYarnLock(v1))).toEqual({
      components: [
        { name: "braces", version: "2.3.2" },
        { name: "@babel/core", version: "7.29.7" },
      ],
      unmatched: 0,
    });
    const berry = ['"braces@npm:^2.3.1":', "  version: 2.3.2", "  checksum: 10c0/abc"].join("\n");
    expect(inventory(parseYarnLock(berry))).toEqual({ components: [{ name: "braces", version: "2.3.2", integrity: "10c0/abc" }], unmatched: 0 });
  });
});

describe("declared lockfile range edges (#1774)", () => {
  it.each([2, 3])("reads npm v%s owner/path/section identities without duplicate manifest or workspace facts", (lockfileVersion) => {
    const ranges = parsePackageLock(JSON.stringify({ lockfileVersion, packages: {
      "": { version: "1.0.0", dependencies: { direct: "^1.0.0" }, peerDependencies: { compatible: "*" } },
      "node_modules/parent": { version: "1.0.0", dependencies: { child: "^1.0.0", exact: "1.0.0", remote: "git+https://user:secret@example.invalid/repo.git#abc" }, optionalDependencies: { child: "^1.0.0" }, devDependencies: { tool: "~2.0.0" }, peerDependencies: { peer: "*" } },
      "node_modules/other": { version: "2.0.0", dependencies: { child: "^1.0.0" } },
      "node_modules/parent/node_modules/other": { version: "3.0.0", dependencies: { child: "^1.0.0" } },
      "node_modules/local": { link: true, resolved: "packages/local", dependencies: { duplicate: "*" }, peerDependencies: { compatible: "*" } },
      "packages/local": { name: "local", version: "1.0.0", dependencies: { duplicate: "*" }, peerDependencies: { compatible: "*" } },
      "not-a-package-path": { version: "1.0.0", dependencies: { unreadOwner: "*" } },
      "node_modules/bad-value": { version: "1.0.0", dependencies: { object: { version: "^1.0.0" }, numeric: 2, valid: "1.0.0" } },
      "node_modules/bad-map": { version: "1.0.0", dependencies: "*" },
      "node_modules/..": { version: "1.0.0", dependencies: { child: "*" } },
      "node_modules/bad-child": { version: "1.0.0", dependencies: { "@scope/..": "*" } },
    } })).ranges;
    expect(ranges).toMatchObject({ schemaVersion: 1, source: "package-lock.json", sourceVersion: String(lockfileVersion), status: "partial", examined: 14, unread: 6, unsupported: 0, excluded: { root: 1, workspace: 1, link: 1, peer: 4 } });
    expect(ranges.edges).toHaveLength(8);
    expect(new Set(ranges.edges.map((edge) => edge.identity)).size).toBe(8);
    expect(ranges.edges.filter((edge) => edge.name === "child")).toHaveLength(4);
    expect(ranges.edges.every((edge) => !edge.direct && edge.format === "package-lock")).toBe(true);
    expect(ranges.edges.find((edge) => edge.ownerPath === "node_modules/parent/node_modules/other")).toMatchObject({ ownerName: "other", ownerVersion: "3.0.0", name: "child", range: "^1.0.0", section: "dependencies" });
    expect(ranges.edges.find((edge) => edge.name === "remote")?.range).toContain("user:secret@");
    expect(ranges.edges.map((edge) => edge.identity).join("\n")).not.toContain("secret");
    expect(ranges.edges.map((edge) => edge.identity)).toEqual(ranges.edges.map((edge) => edge.identity).sort());
  });

  it("reports v1 requires ranges and unknown-version maps as present but unread", () => {
    const v1 = parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: { parent: { version: "1.0.0", requires: { child: "^2.0.0", remote: "github:owner/repo" } } } }));
    expect(v1.components).toEqual([{ name: "parent", version: "1.0.0" }]);
    expect(v1.ranges).toMatchObject({ sourceVersion: "1", status: "unsupported", edges: [], examined: 2, unread: 2, unsupported: 1 });
    expect(v1.ranges.detail).toContain("requires maps can retain declared ranges");
    const future = parsePackageLock(JSON.stringify({ lockfileVersion: 99, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^2.0.0" } } } }));
    expect(future.ranges).toMatchObject({ sourceVersion: "99", status: "unsupported", edges: [], unread: 1 });
  });

  it.each(["5.4", "6.0", "9.0"])("discloses pnpm %s specifiers separately from resolved references and peer compatibility", (version) => {
    const declarations = version === "5.4"
      ? "specifiers:\n  child: ^2.0.0\ndependencies:\n  child: 2.0.1\n"
      : "importers:\n  .:\n    dependencies:\n      child:\n        specifier: ^2.0.0\n        version: 2.0.1\n";
    const key = version === "5.4" ? "/parent/1.0.0" : version === "6.0" ? "/parent@1.0.0" : "parent@1.0.0";
    const parsed = parsePnpmLock(`lockfileVersion: '${version}'\n${declarations}packages:\n  '${key}':\n    dependencies:\n      child: 2.0.1\n    peerDependencies:\n      react: ^18.0.0\n`);
    expect(parsed.components).toEqual([{ name: "parent", version: "1.0.0" }]);
    expect(parsed.ranges).toMatchObject({ sourceVersion: version, status: "present-but-unread", edges: [], unread: 1, unsupported: 1, excluded: { peer: 1 } });
    expect(parsed.ranges.detail).toContain("1 importer/root specifier value(s) are present but unread");
    expect(parsed.ranges.detail).toContain("1 package/snapshot dependency reference(s)");
  });

  it("keeps classic and Berry selector/dependency ranges visibly present but unread", () => {
    for (const [text, sourceVersion] of [
      ['# yarn lockfile v1\nparent@^1.0.0:\n  version "1.0.0"\n  dependencies:\n    child "^2.0.0"\n  peerDependencies:\n    react "^18.0.0"\n', "classic v1"],
      ['__metadata:\n  version: 8\n\n"parent@npm:^1.0.0":\n  version: 1.0.0\n  dependencies:\n    child: "npm:^2.0.0"\n  peerDependencies:\n    react: ^18.0.0\n', "Berry 8"],
    ]) {
      const { ranges } = parseYarnLock(text!);
      expect(ranges).toMatchObject({ sourceVersion, status: "present-but-unread", edges: [], examined: 2, unread: 2, excluded: { peer: 1 } });
      expect(ranges.detail).toContain("1 selector range(s) and 1 dependency-block value(s) are present but unread");
    }
  });
});

// #1079: completeness used to be `components.length > 0`, so a parser that recovered 1 of 900
// entries still reported "complete" — the exact partial-presented-as-whole shape the module header
// names as THE risk with an SBOM, addressed only for the empty-parse case.
describe("a parser that skips entries reports them (#1079)", () => {
  it("counts package-lock entries with no version, and never counts a workspace link", () => {
    const text = JSON.stringify({
      packages: {
        "": { version: "1.0.0" },
        "node_modules/axios": { version: "1.7.2" },
        "node_modules/mystery": {}, // present in the tree, unresolvable — the shortfall
        "node_modules/local-pkg": { resolved: "packages/local", link: true }, // a symlink, not an artifact
      },
    });
    expect(parsePackageLock(text)).toMatchObject({ components: [{ name: "axios" }], unmatched: 1 });
  });

  it("counts a pnpm package key the version regex cannot resolve", () => {
    const text = ["packages:", "", "  '@babel/core@7.29.7':", "  'weird-entry-without-a-version':"].join("\n");
    expect(parsePnpmLock(text).unmatched).toBe(1);
  });

  it("counts a yarn header that never reaches a version line", () => {
    const text = ['braces@^2.3.1:', '  version "2.3.2"', '', '"truncated@^1.0.0":'].join("\n");
    expect(parseYarnLock(text)).toMatchObject({ components: [{ name: "braces" }], unmatched: 1 });
  });
});

describe("CycloneDX document", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sbom-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("is a valid-shaped CycloneDX 1.5 BOM with purls", () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2" }, "node_modules/@next/env": { version: "14.2.35" } } }));
    const bom = bomOf(dir);
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.5");
    expect(bom.metadata.component.name).toBe("t");
    expect(bom.components).toHaveLength(2);
    expect(bom.components[0]).toMatchObject({ type: "library", name: "axios", version: "1.7.2", purl: "pkg:npm/axios@1.7.2" });
    // A scoped name's "@" is percent-encoded in a purl; the namespace separator is not.
    expect(bom.components[1].purl).toBe("pkg:npm/%40next/env@14.2.35");
  });

  it("marks dev-only dependencies out of the shipped artifact", () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/vitest": { version: "3.2.6", dev: true } } }));
    expect(bomOf(dir).components[0].scope).toBe("optional");
  });

  // #1079: the two fields an enterprise buyer's checklist actually looks for, both already in the
  // lockfile Harvey parses. The SRI hash is base64; CycloneDX wants hex, and a digest emitted in
  // the wrong encoding fails verification more confusingly than an absent one.
  it("emits CycloneDX licenses and hashes, converting SRI base64 to hex", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2", license: "MIT", integrity: "sha512-3q2+7w==" } } }),
    );
    const c = bomOf(dir).components[0];
    expect(c.licenses).toEqual([{ license: { id: "MIT" } }]);
    expect(c.hashes).toEqual([{ alg: "SHA-512", content: Buffer.from("3q2+7w==", "base64").toString("hex") }]);
  });

  it("uses CycloneDX `expression` for a compound license — an expression in the id field fails schema validation", () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/x": { version: "1.0.0", license: "(MIT OR Apache-2.0)" } } }));
    expect(bomOf(dir).components[0].licenses).toEqual([{ expression: "(MIT OR Apache-2.0)" }]);
  });

  it("states license/hash coverage rather than letting a half-populated field read as the whole picture", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0", license: "MIT" }, "node_modules/b": { version: "2.0.0" } } }),
    );
    const props: { name: string; value: string }[] = bomOf(dir).metadata.properties;
    expect(props.find((p) => p.name === "harvey:license-coverage")?.value).toContain("1/2");
    expect(props.find((p) => p.name === "harvey:hash-coverage")?.value).toContain("0/2");
  });
});

// #1213: licenseScope is checkLicenseCompliance's candidate set, and the whole point is that it is
// the RESOLVED TREE — the manifest-scoped list it replaced (#1079/#1099) could never submit a
// transitively-reached copyleft package to the check at all.
describe("licenseScope (#1213)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sbom-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("carries the whole tree, marking which packages a manifest actually declared", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2", license: "MIT" }, "node_modules/@img/sharp-libvips": { version: "1.2.4", license: "LGPL-3.0-or-later" } } }),
    );
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { axios: "^1.7.2" } }));
    const scope = licenseScope(dir);
    expect(scope.candidates).toEqual([
      { name: "axios", version: "1.7.2", license: "MIT", direct: true },
      { name: "@img/sharp-libvips", version: "1.2.4", license: "LGPL-3.0-or-later", direct: false },
    ]);
    expect([scope.direct, scope.transitive]).toEqual([1, 1]);
    expect(scope.completeness).toBe("complete");
  });

  it("keeps two versions of one package apart instead of letting the later parse win", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/dep": { version: "1.0.0", license: "MIT" }, "node_modules/other/node_modules/dep": { version: "2.0.0", license: "GPL-3.0" } } }),
    );
    expect(licenseScope(dir).candidates.map((c) => `${c.name}@${c.version}=${c.license}`)).toEqual(["dep@1.0.0=MIT", "dep@2.0.0=GPL-3.0"]);
  });

  // An optionalDependency the lockfile skipped, or any manifest name on a target with no lockfile,
  // still has to reach the registry fallback rather than dropping out of the candidate set.
  it("keeps a manifest-declared name the tree never resolved", () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2" } } }));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { axios: "^1.7.2" }, optionalDependencies: { fsevents: "2.3.3" } }));
    expect(licenseScope(dir).candidates).toContainEqual({ name: "fsevents", direct: true });
  });

  it("keeps escaped workspace manifests out of the exact declared license population", () => {
    const outside = mkdtempSync(join(tmpdir(), "sbom-workspace-outside-"));
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        name: "root",
        workspaces: ["./packages//*", "../sbom-workspace-outside-*", "linked"],
        dependencies: { rootdep: "1.0.0" },
      }));
      mkdirSync(join(dir, "packages", "zeta"), { recursive: true });
      mkdirSync(join(dir, "packages", "alpha"), { recursive: true });
      writeFileSync(join(dir, "packages", "zeta", "package.json"), JSON.stringify({ dependencies: { zetadep: "1.0.0" } }));
      writeFileSync(join(dir, "packages", "alpha", "package.json"), JSON.stringify({ dependencies: { alphadep: "1.0.0" } }));
      writeFileSync(join(outside, "package.json"), JSON.stringify({ dependencies: { escapeddep: "1.0.0" } }));
      symlinkSync(outside, join(dir, "linked"), "dir");

      const scope = licenseScope(dir);
      expect(scope.candidates).toEqual([
        { name: "rootdep", version: "1.0.0", direct: true },
        { name: "alphadep", direct: true },
        { name: "zetadep", direct: true },
      ]);
      expect(scope.declaredFrom).toEqual({
        manifests: 3,
        source: "package.json#workspaces",
        unresolvedGlobs: ["../sbom-workspace-outside-*", "linked"],
        unreadable: [],
      });
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

// The failure mode that makes an SBOM worse than none: a partial inventory that reads as whole.
describe("completeness is always stated", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sbom-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("claims complete only when a lockfile actually resolved the tree", () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2" } } }));
    expect(buildSbom(dir).warning).toBeUndefined();
    expect(bomOf(dir).compositions[0].aggregate).toBe("complete");
  });

  it("degrades to the manifest and says so when there is no lockfile", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { axios: "^1.7.2" }, devDependencies: { vitest: "^3.0.0" } }));
    const { bom, warning } = buildSbom(dir);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- reading the emitted JSON
    const b = bom as any;
    expect(b.components.map((c: { name: string }) => c.name)).toEqual(["axios", "vitest"]);
    expect(b.compositions[0].aggregate).toBe("incomplete");
    expect(warning).toContain("transitive tree is NOT included");
    expect(b.metadata.properties.find((p: { name: string }) => p.name === "harvey:completeness").value).toBe("incomplete");
  });

  it("an unparseable lockfile degrades loudly instead of yielding a thin BOM that looks complete", () => {
    writeFileSync(join(dir, "package-lock.json"), "{ this is not json");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { axios: "^1.7.2" } }));
    const { warning } = buildSbom(dir);
    expect(warning).toContain("package-lock.json is present but Harvey could not extract components");
    expect(bomOf(dir).compositions[0].aggregate).toBe("incomplete");
    expect(collectDependencies(dir).rangeScopes[0]).toMatchObject({ source: "package-lock.json", sourceVersion: "unknown", status: "unreadable", unread: 1, edges: [] });
  });

  it("names shrinkwrap and an unselected sibling lockfile without quietly admitting their ranges", () => {
    const text = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^2.0.0" } } } });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { direct: "1.0.0" } }));
    writeFileSync(join(dir, "npm-shrinkwrap.json"), text);
    expect(collectDependencies(dir).rangeScopes[0]).toMatchObject({ source: "npm-shrinkwrap.json", format: "npm-shrinkwrap", sourceVersion: "3", status: "present-but-unread", unread: 1, unsupported: 1, edges: [] });
    expect(buildSbom(dir).warning).toContain("npm-shrinkwrap.json are present, but no supported resolved-tree parser selected them");
    writeFileSync(join(dir, "package-lock.json"), text);
    const source = collectDependencies(dir);
    expect(source.rangeScopes.map((scope) => [scope.source, scope.edges.length, scope.unread])).toEqual([
      ["package-lock.json", 1, 0], ["npm-shrinkwrap.json", 0, 1],
    ]);
    expect(source.rangeScopes[1]?.detail).toContain("package-lock.json has precedence");
  });

  it("a lockfile Harvey only partly resolved is INCOMPLETE, however many components it did recover", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/axios": { version: "1.7.2" }, "node_modules/mystery": {} } }),
    );
    const { warning } = buildSbom(dir);
    expect(warning).toContain("1 of 2 entries could not be resolved");
    expect(bomOf(dir).compositions[0].aggregate).toBe("incomplete");
  });

  it("an empty BOM says it is empty, not that the project has no dependencies", () => {
    const src = collectDependencies(dir);
    expect(src.completeness).toBe("unknown");
    expect(src.note).toContain("not a dependency-free project");
  });
});
