import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSbom, collectDependencies, parsePackageLock, parsePnpmLock, parseYarnLock } from "./sbom.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the BOM is emitted as plain JSON; tests read it as a consumer would.
const bomOf = (dir: string): any => buildSbom(dir, { targetName: "t", timestamp: "2026-07-23T00:00:00.000Z" }).bom;

describe("lockfile parsing", () => {
  it("reads resolved versions and the dev flag from package-lock v2/v3", () => {
    const text = JSON.stringify({
      packages: {
        "": { version: "1.0.0" }, // the root project is not a component of itself
        "node_modules/axios": { version: "1.7.2" },
        "node_modules/vitest": { version: "3.2.6", dev: true },
        "node_modules/@next/env": { version: "14.2.35" },
        "node_modules/foo/node_modules/axios": { version: "0.21.1" }, // a nested duplicate is its own component
      },
    });
    expect(parsePackageLock(text)).toEqual([
      { name: "axios", version: "1.7.2" },
      { name: "vitest", version: "3.2.6", dev: true },
      { name: "@next/env", version: "14.2.35" },
      { name: "axios", version: "0.21.1" },
    ]);
  });

  it("falls back to the v1 nested `dependencies` tree", () => {
    const text = JSON.stringify({ dependencies: { axios: { version: "1.7.2", dependencies: { follow: { version: "1.15.4" } } } } });
    expect(parsePackageLock(text)).toEqual([
      { name: "axios", version: "1.7.2" },
      { name: "follow", version: "1.15.4" },
    ]);
  });

  it("reads every pnpm key shape across lockfile versions", () => {
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
    expect(parsePnpmLock(text)).toEqual([
      { name: "@babel/core", version: "7.29.7" },
      { name: "braces", version: "2.3.2" },
      { name: "minimist", version: "1.2.0" },
      { name: "react", version: "18.2.0" },
    ]);
  });

  it("reads both yarn v1 and Berry entries", () => {
    const v1 = ['braces@^2.3.1:', '  version "2.3.2"', '', '"@babel/core@^7.0.0":', '  version "7.29.7"'].join("\n");
    expect(parseYarnLock(v1)).toEqual([
      { name: "braces", version: "2.3.2" },
      { name: "@babel/core", version: "7.29.7" },
    ]);
    const berry = ['"braces@npm:^2.3.1":', "  version: 2.3.2"].join("\n");
    expect(parseYarnLock(berry)).toEqual([{ name: "braces", version: "2.3.2" }]);
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
  });

  it("an empty BOM says it is empty, not that the project has no dependencies", () => {
    const src = collectDependencies(dir);
    expect(src.completeness).toBe("unknown");
    expect(src.note).toContain("not a dependency-free project");
  });
});
