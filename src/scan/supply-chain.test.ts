import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkInstallScripts, checkKnownIoc, checkLicenseCompliance, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, classifyLicense } from "./supply-chain.js";

describe("checkTyposquat", () => {
  it("flags a name one edit from a popular package", () => {
    const findings = checkTyposquat(["expres", "react"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("expres");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag an exact popular-package match", () => {
    expect(checkTyposquat(["express", "react"])).toEqual([]);
  });

  it("does not flag unrelated names with no close popular match", () => {
    expect(checkTyposquat(["my-internal-utils"])).toEqual([]);
  });
});

describe("checkUnpinnedDependencies", () => {
  it("flags caret/tilde/wildcard ranges as high precision", () => {
    const findings = checkUnpinnedDependencies({ react: "^18.2.0", zod: "3.22.0", lodash: "*" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("react@^18.2.0");
    expect(findings[0]?.evidence).toContain("lodash@*");
    expect(findings[0]?.evidence).not.toContain("zod@");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("returns no finding when every dependency is exactly pinned", () => {
    expect(checkUnpinnedDependencies({ react: "18.2.0", zod: "3.22.0" })).toEqual([]);
  });
});

describe("checkNonRegistryDependencies", () => {
  it("flags git/url/file dependency sources at review tier", () => {
    const findings = checkNonRegistryDependencies({
      "left-pad": "git+https://github.com/left-pad/left-pad.git",
      local: "file:../local-pkg",
      react: "^18.2.0",
      zod: "3.22.0",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("left-pad@git+https://github.com/left-pad/left-pad.git");
    expect(findings[0]?.evidence).toContain("local@file:../local-pkg");
    expect(findings[0]?.evidence).not.toContain("react@");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag registry semver ranges", () => {
    expect(checkNonRegistryDependencies({ react: "^18.2.0", zod: "3.22.0", next: "~14.2.5" })).toEqual([]);
  });
});

describe("checkInstallScripts", () => {
  it("flags a postinstall lifecycle script at review tier", () => {
    const findings = checkInstallScripts({ build: "next build", postinstall: "node ./setup.js" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("postinstall");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag when no install lifecycle hooks are present", () => {
    expect(checkInstallScripts({ build: "next build", test: "vitest" })).toEqual([]);
  });
});

describe("checkKnownIoc", () => {
  it("flags a known-malicious package name at high precision", () => {
    const findings = checkKnownIoc(["react", "flatmap-stream"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-IOC-flatmap-stream");
    expect(findings[0]?.severity).toBe("Critical");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("does not flag a legitimate package that merely has a postinstall (esbuild)", () => {
    expect(checkKnownIoc(["esbuild", "next", "react-dom"])).toEqual([]);
  });

  it("encodes the manifest path and package name into the location", () => {
    const finding = checkKnownIoc(["flatmap-stream"], "fixtures/legacy-app/package.json")[0];
    expect(finding?.location).toBe("fixtures/legacy-app/package.json (flatmap-stream)");
  });
});

describe("checkLockfilePresence", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("flags a project directory with no lockfile", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-lockfile-"));
    expect(checkLockfilePresence(dir)).toHaveLength(1);
  });

  it("reports the caller's label as the location instead of the scratch path", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-lockfile-"));
    expect(checkLockfilePresence(dir, "fixtures/legacy-app")[0]?.location).toBe("fixtures/legacy-app");
  });

  it("does not flag a directory with pnpm-lock.yaml present", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-lockfile-"));
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    expect(checkLockfilePresence(dir)).toEqual([]);
  });
});

describe("checkSlopsquat", () => {
  it("does not flag a package the registry confirms exists (200)", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 200 })) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react"], fetchImpl);
    expect(findings).toEqual([]);
  });

  it("flags a package the registry confirms does not exist (404) at high precision", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 404 })) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react-supabase-helpers"], fetchImpl);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("react-supabase-helpers");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("checks scoped package names against the registry with the name URL-encoded", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (url: string | URL) => {
      calls.push(url.toString());
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    await checkSlopsquat(["@supabase/supabase-js"], fetchImpl);
    expect(calls[0]).toBe("https://registry.npmjs.org/%40supabase%2Fsupabase-js");
  });

  it("degrades gracefully (no finding, no throw) on a network error", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = vi.fn(async () => {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    }) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react"], fetchImpl);
    expect(findings).toEqual([]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("indeterminate"));
    warn.mockRestore();
  });

  it("does not flag on a non-404 error status (e.g. registry rate-limiting) — indeterminate, not confirmed missing", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = vi.fn(async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react"], fetchImpl);
    expect(findings).toEqual([]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("indeterminate"));
    warn.mockRestore();
  });
});

describe("classifyLicense", () => {
  it("classifies a plain permissive SPDX id as permissive", () => {
    expect(classifyLicense("MIT")).toBe("permissive");
    expect(classifyLicense("Apache-2.0")).toBe("permissive");
  });

  it("classifies a strong-copyleft SPDX id as copyleft", () => {
    expect(classifyLicense("GPL-3.0")).toBe("copyleft");
    expect(classifyLicense("AGPL-3.0-only")).toBe("copyleft");
    expect(classifyLicense("LGPL-2.1")).toBe("copyleft");
  });

  it("treats missing/UNLICENSED/unrecognized as unknown, never a permissive default", () => {
    expect(classifyLicense(undefined)).toBe("unknown");
    expect(classifyLicense("")).toBe("unknown");
    expect(classifyLicense("UNLICENSED")).toBe("unknown");
    expect(classifyLicense("Some-Made-Up-License")).toBe("unknown");
  });

  it("an OR expression is permissive if any alternative is (the chooser picks the permissive one)", () => {
    expect(classifyLicense("(MIT OR GPL-2.0)")).toBe("permissive");
    expect(classifyLicense("GPL-3.0 OR MIT")).toBe("permissive");
  });

  it("an OR expression of only copyleft alternatives stays copyleft", () => {
    expect(classifyLicense("GPL-2.0 OR AGPL-3.0")).toBe("copyleft");
  });
});

describe("checkLicenseCompliance", () => {
  const packument = (body: unknown, status = 200) =>
    vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

  it("does not flag a dependency under a permissive license", async () => {
    const fetchImpl = packument({ license: "MIT" });
    const findings = await checkLicenseCompliance({ react: "^18.2.0" }, fetchImpl);
    expect(findings).toEqual([]);
  });

  it("flags a copyleft-licensed dependency at high precision with the SPDX id in evidence", async () => {
    const fetchImpl = packument({ license: "GPL-3.0" });
    const findings = await checkLicenseCompliance({ "gpl-lib": "1.0.0" }, fetchImpl);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-COPYLEFT-gpl-lib");
    expect(findings[0]?.category).toBe("License compliance");
    expect(findings[0]?.evidence).toContain("GPL-3.0");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("flags a missing license field as review-tier, never a silent skip", async () => {
    const fetchImpl = packument({});
    const findings = await checkLicenseCompliance({ "no-license-lib": "1.0.0" }, fetchImpl);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-UNKNOWN-no-license-lib");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("flags npm's UNLICENSED marker the same as a missing license — never a permissive default", async () => {
    const fetchImpl = packument({ license: "UNLICENSED" });
    const findings = await checkLicenseCompliance({ "private-lib": "1.0.0" }, fetchImpl);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-UNKNOWN-private-lib");
  });

  it("degrades gracefully (no finding, no throw) on a network error", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = vi.fn(async () => {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    }) as unknown as typeof fetch;
    const findings = await checkLicenseCompliance({ react: "^18.2.0" }, fetchImpl);
    expect(findings).toEqual([]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("indeterminate"));
    warn.mockRestore();
  });
});
