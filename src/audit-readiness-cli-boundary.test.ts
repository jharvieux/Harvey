import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertDistinctArtifactDestinations,
  captureReadinessAuthorization,
  isCurrentArtifact,
  writeCurrentArtifact,
} from "./audit-readiness-cli-boundary.js";

let scratch: string | undefined;
const root = () => scratch ??= mkdtempSync(join(tmpdir(), "harvey-cli-boundary-"));
afterEach(() => { if (scratch) rmSync(scratch, { recursive: true, force: true }); scratch = undefined; });

describe("readiness CLI public boundary (#1897)", () => {
  it("reads safe redaction values from a rejected grant, but reads no values when any name is unsafe", () => {
    const valid = join(root(), "valid.json");
    writeFileSync(valid, JSON.stringify({ approvedEnvNames: ["READINESS_TOKEN"], unsupported: true }));
    expect(captureReadinessAuthorization(valid, { READINESS_TOKEN: "private-canary" })).toMatchObject({
      parsed: true, namesValidated: true, redactionNames: ["READINESS_TOKEN"], redactionValues: ["private-canary"],
    });

    const unsafe = join(root(), "unsafe.json");
    writeFileSync(unsafe, JSON.stringify({ approvedEnvNames: ["READINESS_TOKEN", "NODE_OPTIONS"] }));
    const observed = new Proxy({ READINESS_TOKEN: "private-canary", NODE_OPTIONS: "private-runtime" }, {
      get() { throw new Error("environment value was read"); },
      getOwnPropertyDescriptor() { throw new Error("environment value was inspected"); },
    });
    expect(() => captureReadinessAuthorization(unsafe, observed)).not.toThrow();
    expect(captureReadinessAuthorization(unsafe, observed)).toMatchObject({ namesValidated: false, redactionNames: [], redactionValues: [] });
  });

  it("rejects lexical, symlink and hard-link destination aliases", () => {
    const file = join(root(), "artifact.json");
    writeFileSync(file, "old\n");
    const symlink = join(root(), "symlink.json");
    const hardlink = join(root(), "hardlink.json");
    symlinkSync(file, symlink);
    linkSync(file, hardlink);
    for (const alias of [file, symlink, hardlink]) {
      expect(() => assertDistinctArtifactDestinations([
        { flag: "--readiness-plan-out", path: file },
        { flag: "--readiness-execute-out", path: alias },
      ])).toThrow(/destinations alias/);
    }
    expect(readFileSync(file, "utf8")).toBe("old\n");
  });

  it("requires a same-run byte/hash receipt and invalidates it when current bytes change", () => {
    const file = join(root(), "artifact.json");
    const writes = new Map<string, { bytes: number; sha256: string }>();
    writeFileSync(file, "stale\n");
    expect(isCurrentArtifact(file, writes)).toBe(false);
    writeCurrentArtifact(file, "current\n", writes);
    expect(isCurrentArtifact(file, writes)).toBe(true);
    writeFileSync(file, "altered\n");
    expect(isCurrentArtifact(file, writes)).toBe(false);
  });

  it("resolves aliases through an existing symlinked parent", () => {
    const physical = join(root(), "physical");
    const linked = join(root(), "linked");
    mkdirSync(physical);
    symlinkSync(physical, linked);
    expect(() => assertDistinctArtifactDestinations([
      { flag: "--out", path: join(physical, "new.json") },
      { flag: "--findings-out", path: join(linked, "new.json") },
    ])).toThrow(/destinations alias/);
  });
});
