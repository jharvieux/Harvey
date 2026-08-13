import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverImplementationClosure, discoverTransitiveImplementationFiles } from "./implementation-closure.js";

describe("shared implementation closure", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): string => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-implementation-closure-"));
    dirs.push(dir);
    writeFileSync(join(dir, "entry.ts"), 'import { helper } from "./helper.js"; helper();\n');
    writeFileSync(join(dir, "helper.ts"), "export const helper = (): void => {};\n");
    return dir;
  };

  it("discovers a newly imported helper and records the consuming edge", () => {
    const dir = fixture();
    const receipt = discoverImplementationClosure([join(dir, "entry.ts")]);
    expect(receipt.files).toEqual([join(dir, "entry.ts"), join(dir, "helper.ts")]);
    expect(receipt.edges).toContainEqual(expect.objectContaining({ from: join(dir, "entry.ts"), to: join(dir, "helper.ts"), kind: "static" }));
    expect(receipt.uncertainties).toEqual([]);
  });

  it("retains dynamic and unresolved edges as fail-open evidence", () => {
    const dir = fixture();
    writeFileSync(join(dir, "entry.ts"), 'const name = "helper"; void import(`./${name}.js`); void import("./missing.js");\n');
    const receipt = discoverImplementationClosure([join(dir, "entry.ts")]);
    expect(receipt.uncertainties.map((item) => item.kind).sort()).toEqual(["dynamic", "unresolved"]);
    expect(() => discoverTransitiveImplementationFiles([join(dir, "entry.ts")])).toThrow(/implementation closure dynamic|implementation closure unresolved/);
  });

  it("records a missing or unreadable root instead of returning an empty clean closure", () => {
    const dir = fixture();
    const receipt = discoverImplementationClosure([join(dir, "absent.ts")]);
    expect(receipt.files).toEqual([]);
    expect(receipt.uncertainties).toContainEqual(expect.objectContaining({ kind: "unresolved", detail: expect.stringContaining("missing") }));
  });
});
