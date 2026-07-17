// Intent: runMechanicalScan's skipNetworkChecks option (added alongside the dry-run harness's
// network-independence fix) must actually gate the two live npm-registry calls
// (checkSlopsquat, checkLicenseCompliance) — the assertion is "never invoked", not "returned no
// findings" (which a network hiccup could also produce and wrongly pass). The other sub-scanners
// (secrets, semgrep) shell out to real binaries and are mocked here purely so this test stays
// fast and offline like the rest of the suite (matching pnpm verify's own deterministic-offline
// convention) — they aren't what this test is about.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const checkSlopsquat = vi.fn(async () => []);
const checkLicenseCompliance = vi.fn(async () => []);

vi.mock("./supply-chain.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./supply-chain.js")>();
  return { ...actual, checkSlopsquat, checkLicenseCompliance };
});
vi.mock("./secrets.js", () => ({ scanSecrets: vi.fn(() => []) }));
vi.mock("./semgrep.js", () => ({
  runSemgrep: vi.fn(() => ""),
  parseSemgrepFindings: vi.fn(() => []),
  checkMissingCsp: vi.fn(() => []),
  checkPublicDirSensitive: vi.fn(() => []),
}));

const { runMechanicalScan } = await import("./mechanical.js");

describe("runMechanicalScan skipNetworkChecks", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-test-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", dependencies: { react: "18.2.0" } }));
    checkSlopsquat.mockClear();
    checkLicenseCompliance.mockClear();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("skips the live npm-registry checks when set", async () => {
    await runMechanicalScan({ dir, skipNetworkChecks: true });
    expect(checkSlopsquat).not.toHaveBeenCalled();
    expect(checkLicenseCompliance).not.toHaveBeenCalled();
  });

  it("still runs the live npm-registry checks by default", async () => {
    await runMechanicalScan({ dir });
    expect(checkSlopsquat).toHaveBeenCalledWith(["react"]);
    expect(checkLicenseCompliance).toHaveBeenCalledWith({ react: "18.2.0" });
  });
});
