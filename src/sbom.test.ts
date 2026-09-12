import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildSbom, collectDependencies, licenseScope, parsePackageLock, parsePnpmLock, parseYarnLock } from "./sbom.js";
import { checkLicenseCompliance } from "./scan/supply-chain.js";

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

  it.each([1, 2, 3])("uses metadata names for alias installations in package-lock v%s, while retaining path-name fallbacks and repeated versions", (lockfileVersion) => {
    const aliases = lockfileVersion === 1
      ? { dependencies: {
        "wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", dependencies: { "string-width-cjs": { name: "string-width", version: "4.2.3" } } },
        ordinary: { version: "1.0.0" },
      } }
      : { packages: {
        "node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0" },
        "node_modules/parent/node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "6.0.0" },
        "node_modules/ordinary": { version: "1.0.0" },
      } };
    expect(inventory(parsePackageLock(JSON.stringify({ lockfileVersion, ...aliases })))).toEqual({
      components: lockfileVersion === 1
        ? [{ name: "wrap-ansi", version: "7.0.0" }, { name: "string-width", version: "4.2.3" }, { name: "ordinary", version: "1.0.0" }]
        : [{ name: "wrap-ansi", version: "7.0.0" }, { name: "wrap-ansi", version: "6.0.0" }, { name: "ordinary", version: "1.0.0" }],
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
  it.each([2, 3])("uses an alias installation's metadata name for its v%s range owner", (lockfileVersion) => {
    const { edges } = parsePackageLock(JSON.stringify({ lockfileVersion, packages: {
      "node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", dependencies: { "strip-ansi": "^6.0.1" } },
    } })).ranges;
    expect(edges).toEqual([expect.objectContaining({ ownerPath: "node_modules/wrap-ansi-cjs", ownerName: "wrap-ansi", ownerVersion: "7.0.0", name: "strip-ansi", range: "^6.0.1" })]);
  });

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

  it.each([
    ["importer map", { importers: "malformed" }],
    ["null importer map", { importers: null }],
    ["array importer map", { importers: [] }],
    ["importer entry", { importers: { ".": "malformed" } }],
    ["dependency map", { importers: { ".": { dependencies: "malformed" } } }],
    ["null dependency map", { importers: { ".": { dependencies: null } } }],
    ["array dependency map", { importers: { ".": { dependencies: [] } } }],
    ["devDependency map", { importers: { ".": { devDependencies: "malformed" } } }],
    ["optionalDependency map", { importers: { ".": { optionalDependencies: "malformed" } } }],
    ["root specifier map", { specifiers: "malformed" }],
    ["importer specifier map", { importers: { ".": { specifiers: "malformed" } } }],
    ["package map", { packages: "malformed" }],
    ["snapshot map", { snapshots: "malformed" }],
    ["package entry", { packages: { "parent@1.0.0": "malformed" } }],
    ["resolved dependency map", { snapshots: { "parent@1.0.0": { dependencies: "malformed" } } }],
    ["peer map", { snapshots: { "parent@1.0.0": { peerDependencies: "malformed" } } }],
  ])("counts a malformed pnpm %s as an unread boundary, never a guessed edge", (_label, fields) => {
    const { ranges } = parsePnpmLock(JSON.stringify({ lockfileVersion: "9.0", ...fields }));
    expect(ranges).toMatchObject({ status: "present-but-unread", edges: [], examined: 1, unread: 1, unsupported: 1, excluded: { peer: 0 } });
    expect(ranges.detail).toContain("0 importer/root specifier value(s)");
    expect(ranges.detail).toContain("1 malformed map boundary");
    expect(ranges.detail).toContain("not guessed dependency edges");
    expect(ranges.detail).toContain("0 package/snapshot dependency reference(s)");
  });

  it("distinguishes absent and empty pnpm maps from present specifiers and malformed boundaries", () => {
    for (const fields of [{}, { importers: {} }, { importers: { ".": { dependencies: {} } } }]) {
      expect(parsePnpmLock(JSON.stringify({ lockfileVersion: "9.0", ...fields })).ranges).toMatchObject({ examined: 0, unread: 0, edges: [] });
    }
    const { ranges } = parsePnpmLock(JSON.stringify({ lockfileVersion: "9.0", importers: {
      ".": { dependencies: { child: { specifier: "^1.0.0", version: "1.0.1" }, untrusted: { specifier: { raw: "unread" } } } },
      "apps/web": { dependencies: "malformed" },
    } }));
    expect(ranges).toMatchObject({ examined: 3, unread: 3, edges: [] });
    expect(ranges.detail).toContain("2 importer/root specifier value(s)");
    expect(ranges.detail).toContain("1 malformed map boundary");
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

  it("delivers alias-only metadata names to the CycloneDX export and license consumer", async () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: {
      "node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", license: "GPL-3.0" },
      "node_modules/ordinary": { version: "1.0.0", license: "MIT" },
    } }));

    expect(bomOf(dir).components).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "wrap-ansi", version: "7.0.0", purl: "pkg:npm/wrap-ansi@7.0.0" }),
      expect.objectContaining({ name: "ordinary", version: "1.0.0", purl: "pkg:npm/ordinary@1.0.0" }),
    ]));
    const scope = licenseScope(dir);
    expect(scope.candidates).toEqual(expect.arrayContaining([
      { name: "wrap-ansi", version: "7.0.0", license: "GPL-3.0", direct: false },
    ]));
    const findings = await checkLicenseCompliance(scope);
    expect(findings.map((finding) => finding.id)).toContain("SUP-LICENSE-COPYLEFT-wrap-ansi@7.0.0");
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

  it.each([1, 2, 3])("reconciles a root npm alias with its package-lock v%s installation", (lockfileVersion) => {
    const lock = lockfileVersion === 1
      ? { dependencies: { "wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", license: "MIT" } } }
      : { packages: { "node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", license: "MIT" } } };
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "wrap-ansi-cjs": "npm:wrap-ansi@7.0.0" } }));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion, ...lock }));

    expect(licenseScope(dir).candidates).toEqual([{ name: "wrap-ansi", version: "7.0.0", license: "MIT", direct: true }]);
  });

  it("reconciles scoped root and workspace aliases only when their installations resolved", () => {
    mkdirSync(join(dir, "packages", "web"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      workspaces: ["packages/*"],
      dependencies: { "root-alias": "npm:root-real@1.0.0", unresolved: "npm:unresolved-real@1.0.0" },
    }));
    writeFileSync(join(dir, "packages", "web", "package.json"), JSON.stringify({ dependencies: { "@team/alias": "npm:@actual/pkg@2.0.0" } }));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
      "node_modules/root-alias": { name: "root-real", version: "1.0.0", license: "MIT" },
      "node_modules/@team/alias": { name: "@actual/pkg", version: "2.0.0", license: "MIT" },
      "node_modules/unresolved-real": { name: "unresolved-real", version: "1.0.0", license: "MIT" },
    } }));

    expect(licenseScope(dir).candidates).toEqual([
      { name: "root-real", version: "1.0.0", license: "MIT", direct: true },
      { name: "@actual/pkg", version: "2.0.0", license: "MIT", direct: true },
      { name: "unresolved-real", version: "1.0.0", license: "MIT", direct: false },
      { name: "unresolved", direct: true },
    ]);
  });

  it.each([
    ["MIT", []],
    ["GPL-3.0", ["SUP-LICENSE-COPYLEFT-wrap-ansi@7.0.0"]],
  ])("passes an actual direct alias to license compliance as %s without an alias registry lookup", async (license, ids) => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "wrap-ansi-cjs": "npm:wrap-ansi@7.0.0" } }));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
      "node_modules/wrap-ansi-cjs": { name: "wrap-ansi", version: "7.0.0", license },
    } }));
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const findings = await checkLicenseCompliance(licenseScope(dir), { fetchImpl });

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(findings.map((finding) => finding.id)).toEqual(ids);
    expect(findings.find((finding) => finding.id.startsWith("SUP-LICENSE-COPYLEFT"))?.evidence ?? "").not.toContain("reached only through the resolved dependency tree");
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

describe("npm alias provenance (#2046 B2)", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "sbom-alias-provenance-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function write(manifest: object, packages: object, members: Record<string, object> = {}): void {
    writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages }));
    for (const [path, body] of Object.entries(members)) {
      mkdirSync(join(dir, path), { recursive: true });
      writeFileSync(join(dir, path, "package.json"), JSON.stringify(body));
    }
  }

  it.each([1, 2, 3])("retains each v%s installation path while deduplicating exported identities", (lockfileVersion) => {
    const alias = { name: "@actual/pkg", version: "1.0.0", license: "MIT" };
    const lock = lockfileVersion === 1 ? { dependencies: {
      "@scope/alias": alias,
      parent: { version: "1.0.0", dependencies: { "@scope/alias": alias } },
    } } : { packages: {
      "node_modules/@scope/alias": alias,
      "node_modules/parent": { version: "1.0.0" },
      "node_modules/parent/node_modules/@scope/alias": alias,
    } };
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion, ...lock }));
    const deps = collectDependencies(dir);
    expect(deps.installations).toEqual([
      { path: "node_modules/@scope/alias", name: "@actual/pkg", version: "1.0.0" },
      { path: "node_modules/parent", name: "parent", version: "1.0.0" },
      { path: "node_modules/parent/node_modules/@scope/alias", name: "@actual/pkg", version: "1.0.0" },
    ]);
    const artifact = join(dir, "sbom.json");
    writeFileSync(artifact, JSON.stringify(buildSbom(dir).bom));
    const exported = JSON.parse(readFileSync(artifact, "utf8")) as { components: object[] };
    expect(exported.components).toHaveLength(2);
    expect(exported.components).toContainEqual(expect.objectContaining({ name: "@actual/pkg", version: "1.0.0", purl: "pkg:npm/%40actual/pkg@1.0.0" }));
    expect(exported.components.every((component) => !("path" in component) && !("installationName" in component))).toBe(true);
  });

  it.each([1, 2, 3])("keeps an unresolved root alias separate from a v%s nested installation of the same target and version", async (lockfileVersion) => {
    const alias = { name: "real", version: "1.0.0", license: "GPL-3.0" };
    const lock = lockfileVersion === 1 ? { dependencies: {
      parent: { version: "1.0.0", license: "MIT", dependencies: { alias } },
    } } : { packages: {
      "node_modules/parent": { version: "1.0.0", license: "MIT", dependencies: { alias: "npm:real@1.0.0" } },
      "node_modules/parent/node_modules/alias": alias,
    } };
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { parent: "1.0.0" }, optionalDependencies: { alias: "npm:real@1.0.0" } }));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion, ...lock }));
    const scope = licenseScope(dir);
    expect(scope.candidates).toEqual([
      { name: "parent", version: "1.0.0", license: "MIT", direct: true },
      { ...alias, direct: false },
      { name: "alias", direct: true },
    ]);
    const findings = await checkLicenseCompliance(scope, { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-COPYLEFT-real@1.0.0", "SUP-LICENSE-00"]);
    expect(findings[0]?.evidence).toContain("reached only through the resolved dependency tree");
    expect(findings[1]?.evidence).toContain("Not assessed: alias");
  });

  it.each([1, 2, 3])("marks only the reachable resolved version as direct in a v%s repeated alias tree", async (lockfileVersion) => {
    const direct = { name: "@actual/pkg", version: "1.2.0", license: "GPL-3.0" };
    const transitive = { name: "@actual/pkg", version: "2.0.0", license: "GPL-3.0" };
    const lock = lockfileVersion === 1 ? { dependencies: {
      "@scope/alias": direct,
      parent: { version: "1.0.0", license: "MIT", dependencies: { "@scope/alias": transitive } },
    } } : { packages: {
      "node_modules/@scope/alias": direct,
      "node_modules/parent": { version: "1.0.0", license: "MIT" },
      "node_modules/parent/node_modules/@scope/alias": transitive,
    } };
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "@scope/alias": "npm:@actual/pkg@^1.0.0" } }));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion, ...lock }));
    const findings = await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-COPYLEFT-@actual/pkg@1.2.0", "SUP-LICENSE-COPYLEFT-@actual/pkg@2.0.0"]);
    expect(findings[0]?.evidence).toContain("declared in a manifest");
    expect(findings[1]?.evidence).toContain("reached only through the resolved dependency tree");
  });

  it.each([
    ["sibling with another target", "packages/b/node_modules/alias", "real-a", "1.0.0"],
    ["sibling with the same target and version", "packages/b/node_modules/alias", "real-b", "2.0.0"],
    ["hoisted other target", "node_modules/alias", "real-a", "1.0.0"],
    ["hoisted incompatible version", "node_modules/alias", "real-b", "^1.0.0"],
  ])("keeps workspace-a's unresolved declaration alongside a resolved %s", async (_label, path, target, range) => {
    write({ workspaces: ["packages/*"] }, {
      [path]: { name: "real-b", version: "2.0.0", license: "MIT" },
    }, {
      "packages/a": { dependencies: { alias: `npm:${target}@${range}` } },
      "packages/b": { dependencies: { alias: "npm:real-b@2.0.0" } },
    });
    const scope = licenseScope(dir);
    expect(scope.candidates).toEqual([
      { name: "real-b", version: "2.0.0", license: "MIT", direct: true },
      { name: "alias", direct: true },
    ]);
    const findings = await checkLicenseCompliance(scope, { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-00"]);
    expect(findings[0]?.evidence).toContain("Not assessed: alias");
  });

  it.each([
    ["different target", { name: "other", version: "1.0.0", license: "GPL-3.0" }],
    ["incompatible version", { name: "real", version: "2.0.0", license: "GPL-3.0" }],
    ["unresolved entry", { name: "real" }],
    ["malformed entry", null],
    ["link", { link: true, resolved: "packages/local" }],
  ])("stops at a nearer %s instead of selecting the matching hoisted alias", async (_label, nearer) => {
    write({ workspaces: ["packages/*"] }, {
      "node_modules/alias": { name: "real", version: "1.0.0", license: "MIT" },
      "packages/a/node_modules/alias": nearer,
    }, { "packages/a": { dependencies: { alias: "npm:real@^1.0.0" } } });
    const scope = licenseScope(dir);
    expect(scope.candidates).toContainEqual({ name: "real", version: "1.0.0", license: "MIT", direct: false });
    expect(scope.candidates).toContainEqual({ name: "alias", direct: true });
    const findings = await checkLicenseCompliance(scope, { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toContain("SUP-LICENSE-00");
    for (const finding of findings.filter((finding) => finding.id.startsWith("SUP-LICENSE-COPYLEFT"))) {
      expect(finding.evidence).toContain("reached only through the resolved dependency tree");
    }
  });

  it.each(["node_modules/@scope/alias", "packages/node_modules/@scope/alias", "packages/group/node_modules/@scope/alias", "packages/group/a/node_modules/@scope/alias"])("resolves scoped workspace aliases from the visible ancestor %s", async (path) => {
    write({ workspaces: ["packages/group/*"] }, {
      [path]: { name: "@actual/pkg", version: "1.2.0", license: "GPL-3.0" },
    }, { "packages/group/a": { devDependencies: { "@scope/alias": "npm:@actual/pkg@~1.2.0" } } });
    expect(licenseScope(dir).candidates).toEqual([{ name: "@actual/pkg", version: "1.2.0", license: "GPL-3.0", direct: true }]);
    const findings = await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-COPYLEFT-@actual/pkg@1.2.0"]);
    expect(findings[0]?.evidence).toContain("declared in a manifest");
  });

  it("resolves each workspace's own conflicting alias target without cross-manifest suppression", async () => {
    write({ workspaces: ["packages/*"] }, {
      "node_modules/@scope/alias": { name: "real-a", version: "1.0.0", license: "GPL-3.0" },
      "packages/b/node_modules/@scope/alias": { name: "real-b", version: "2.0.0", license: "GPL-3.0" },
    }, {
      "packages/a": { dependencies: { "@scope/alias": "npm:real-a@1.0.0" } },
      "packages/b": { dependencies: { "@scope/alias": "npm:real-b@2.0.0" } },
    });
    const findings = await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-COPYLEFT-real-a@1.0.0", "SUP-LICENSE-COPYLEFT-real-b@2.0.0"]);
    expect(findings.every((finding) => finding.evidence.includes("declared in a manifest"))).toBe(true);
  });

  it.each(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"])("reconciles a versionless scoped npm alias declared in %s", async (section) => {
    write({ [section]: { "@scope/alias": "npm:@actual/pkg" } }, {
      "node_modules/@scope/alias": { name: "@actual/pkg", version: "1.0.0", license: "MIT" },
    });
    expect(licenseScope(dir).candidates).toEqual([{ name: "@actual/pkg", version: "1.0.0", license: "MIT", direct: true }]);
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    expect(await checkLicenseCompliance(licenseScope(dir), { fetchImpl })).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("preserves conflicting peer declarations while honoring npm optional overrides", async () => {
    write({
      dependencies: { alias: "npm:old@1.0.0" }, optionalDependencies: { alias: "npm:real@2.0.0" },
    }, { "node_modules/alias": { name: "real", version: "2.0.0", license: "MIT" } });
    expect(await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true })).toEqual([]);
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { alias: "npm:old@1.0.0" }, peerDependencies: { alias: "npm:real@2.0.0" },
    }));
    expect(licenseScope(dir).candidates).toEqual([{ name: "real", version: "2.0.0", license: "MIT", direct: true }, { name: "alias", direct: true }]);
    expect((await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true })).map((finding) => finding.id)).toEqual(["SUP-LICENSE-00"]);
  });

  it.each([
    ["ordinary target installation", "node_modules/real", "real"],
    ["unrelated installation with the declaration's name as metadata", "node_modules/unrelated", "alias"],
    ["scoped basename collision", "node_modules/@scope/alias", "real"],
  ])("does not satisfy a root alias with an %s", async (_label, path, name) => {
    write({ optionalDependencies: { alias: "npm:real@1.0.0" } }, { [path]: { name, version: "1.0.0", license: "MIT" } });
    expect(licenseScope(dir).candidates).toEqual([{ name, version: "1.0.0", license: "MIT", direct: false }, { name: "alias", direct: true }]);
    expect((await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true })).map((finding) => finding.id)).toEqual(["SUP-LICENSE-00"]);
  });

  it.each([
    ["1.2.3", "1.2.3", true], ["1.2.3", "1.2.4", false],
    ["^1.2.3", "1.9.0", true], ["^1.2.3", "2.0.0", false], ["^1.2.3", "1.2.2", false],
    ["^0.2.3", "0.2.9", true], ["^0.2.3", "0.3.0", false], ["^0.0.3", "0.0.4", false],
    ["^0.0", "0.0.4", true], ["^0", "0.9.0", true],
    ["~1.2.3", "1.2.9", true], ["~1.2.3", "1.3.0", false],
    ["1", "1.9.0", true], ["1.x", "2.0.0", false], ["1.2.*", "1.2.9", true],
    [">=1.2.0 <2", "1.3.0", true], [">=1.2.0 <2", "2.0.0", false],
    [">1.2 <=2.1", "1.3.0", true], [">1.2 <=2.1", "1.2.9", false],
    ["^1 || ^3", "3.1.0", true], ["^1 || ^3", "2.1.0", false],
    ["1.2 - 2.3", "2.3.9", true], ["1.2 - 2.3", "2.4.0", false],
    ["1.2.3-beta.1", "1.2.3-beta.1", true], ["^1.2.3-beta.1", "1.2.3-beta.2", true],
    ["1.2.3-beta.9999999999999999999999999998", "1.2.3-beta.9999999999999999999999999999", false],
    ["^1.2.3-beta.2", "1.2.3-beta.1", false], ["^1.2.3-beta.1", "1.2.4-beta.1", false],
    ["^1.2.3", "1.3.0-beta.1", false], ["*", "1.0.0-beta.1", false],
    ["=v1.2.3+build", "1.2.3+other", true], ["*", "1.0.0", true],
    ["latest", "1.0.0", false], ["^1.0.0", "not-a-version", false], ["1.x.3", "1.0.3", false],
  ] as const)("checks alias range %s against resolved version %s (resolved: %s)", async (range, version, resolved) => {
    write({ dependencies: { alias: `npm:real@${range}` } }, { "node_modules/alias": { name: "real", version, license: "GPL-3.0" } });
    expect(licenseScope(dir).candidates).toEqual([
      { name: "real", version, license: "GPL-3.0", direct: resolved },
      ...resolved ? [] : [{ name: "alias", direct: true }],
    ]);
    const findings = await checkLicenseCompliance(licenseScope(dir), { skipRegistry: true });
    expect(findings.map((finding) => finding.id)).toEqual([`SUP-LICENSE-COPYLEFT-real@${version}`, ...resolved ? [] : ["SUP-LICENSE-00"]]);
    expect(findings[0]?.evidence).toContain(resolved ? "declared in a manifest" : "reached only through the resolved dependency tree");
  });

  it("uses the canonical scoped identity for registry fallback and retains an unresolved alias alongside it", async () => {
    write({ dependencies: { installed: "npm:@actual/pkg@1.0.0", missing: "npm:@actual/pkg@1.0.0" } }, {
      "node_modules/installed": { name: "@actual/pkg", version: "1.0.0" },
    });
    const fetchImpl = vi.fn(async (url: string | URL | Request) => new Response(JSON.stringify({ license: "MIT" }), { status: String(url).endsWith("/missing") ? 404 : 200 }));
    const findings = await checkLicenseCompliance(licenseScope(dir), { fetchImpl: fetchImpl as typeof fetch });
    expect(fetchImpl.mock.calls.map(([url]) => String(url))).toEqual(["https://registry.npmjs.org/%40actual%2Fpkg/1.0.0", "https://registry.npmjs.org/missing"]);
    expect(findings.map((finding) => finding.id)).toEqual(["SUP-LICENSE-00"]);
    expect(findings[0]?.evidence).toContain("Not assessed: missing");
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
