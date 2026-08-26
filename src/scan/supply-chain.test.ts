import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parsePackageLock, parsePnpmLock, parseYarnLock, type LicenseCandidate, type LicenseScope } from "../sbom.js";
import { checkDependencyInstallScripts, checkInstallScripts, checkKnownIoc, checkLicenseCompliance, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, classifyLicense, licenseCoverageFinding, NETWORK_SKIPPED_REASON, slopsquatCoverageFinding, supplyChainScopeFinding } from "./supply-chain.js";

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

const declaredIn = (manifest: string, deps: Record<string, string>) => Object.entries(deps).map(([name, range]) => ({ manifest, name, range }));

describe("checkUnpinnedDependencies", () => {
  it("flags caret/tilde/wildcard ranges as high precision", () => {
    const findings = checkUnpinnedDependencies(declaredIn("package.json", { react: "^18.2.0", zod: "3.22.0", lodash: "*" }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("react@^18.2.0");
    expect(findings[0]?.evidence).toContain("lodash@*");
    expect(findings[0]?.evidence).not.toContain("zod@");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("returns no finding when every dependency is exactly pinned", () => {
    expect(checkUnpinnedDependencies(declaredIn("package.json", { react: "18.2.0", zod: "3.22.0" }))).toEqual([]);
  });

  it("rolls repeated owners up without truncating the sorted matching-edge JSON artifact", () => {
    const packages = Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`node_modules/parent-${i}`, {
      version: "1.0.0", dependencies: { "aa-shared": "^1.0.0", [`child-${i}`]: "^2.0.0" },
    }]));
    const { edges } = parsePackageLock(JSON.stringify({ lockfileVersion: 3, packages })).ranges;
    const [finding] = checkUnpinnedDependencies(edges.map((edge) => ({ manifest: edge.source, name: edge.name, range: edge.range, edge })));
    expect(finding?.dependencyRangeEvidence).toMatchObject({ examined: 50, matched: 50, distinctSpecifications: 26, displayedSpecifications: 20 });
    expect(finding?.dependencyRangeEvidence?.edges).toHaveLength(50);
    expect(finding?.evidence).toContain("25 declarations across 25 owners");
    expect(finding?.evidence).toContain("22 more owners");
    expect(finding?.evidence).toContain("6 declarations omitted from prose");
    expect(finding?.evidence.length).toBeLessThan(6000);
    expect(JSON.parse(JSON.stringify(finding)).dependencyRangeEvidence.edges).toEqual(finding?.dependencyRangeEvidence?.edges);
  });

  it.each([
    ["unpinned", checkUnpinnedDependencies, "^2.0.0", "SUP-UNPINNED"],
    ["non-registry", checkNonRegistryDependencies, "git+https://example.invalid/child.git", "SUP-NON-REGISTRY"],
  ] as const)("keeps direct and third-party %s findings distinct for remediation and calibration", (_label, check, range, id) => {
    const edges = parsePackageLock(JSON.stringify({ lockfileVersion: 3, packages: {
      "node_modules/parent": { version: "1.0.0", dependencies: { lodash: range } },
    } })).ranges.edges;
    const findings = check([
      ...declaredIn("package.json", { lodash: "4.17.11", direct: range }),
      ...edges.map((edge) => ({ manifest: edge.source, name: edge.name, range: edge.range, edge })),
    ]);
    expect(findings.map((finding) => finding.id)).toEqual([id, `${id}-TREE`]);
    expect(findings[0]?.location).toBe("package.json");
    expect(findings[0]?.evidence).not.toContain("lodash");
    expect(findings[0]?.dependencyRangeEvidence).toMatchObject({ examined: 2, matched: 1 });
    expect(findings[1]?.location).toBe("package-lock.json (third-party declaration ranges)");
    expect(findings[1]?.evidence).toContain("lodash");
    expect(findings[1]?.dependencyRangeEvidence).toMatchObject({ examined: 1, matched: 1, edges: [{ ownerPath: "node_modules/parent", direct: false }] });
    expect(findings[1]?.fix).toContain("owning dependency");
  });
});

describe("checkNonRegistryDependencies", () => {
  it("flags git/url/file dependency sources at review tier", () => {
    const findings = checkNonRegistryDependencies(
      declaredIn("package.json", {
        "left-pad": "git+https://github.com/left-pad/left-pad.git",
        local: "file:../local-pkg",
        react: "^18.2.0",
        zod: "3.22.0",
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("left-pad@git+https://github.com/left-pad/left-pad.git");
    expect(findings[0]?.evidence).toContain("local@file:../local-pkg");
    expect(findings[0]?.evidence).not.toContain("react@");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag registry semver ranges", () => {
    expect(checkNonRegistryDependencies(declaredIn("package.json", { react: "^18.2.0", zod: "3.22.0", next: "~14.2.5" }))).toEqual([]);
  });
});

describe("checkInstallScripts", () => {
  it("flags a postinstall lifecycle script at review tier", () => {
    const findings = checkInstallScripts([{ label: "package.json", scripts: { build: "next build", postinstall: "node ./setup.js" } }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("postinstall");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag when no install lifecycle hooks are present", () => {
    expect(checkInstallScripts([{ label: "package.json", scripts: { build: "next build", test: "vitest" } }])).toEqual([]);
  });
});

describe("checkDependencyInstallScripts", () => {
  it("flags a resolved transitive install script with its pinned version", () => {
    const findings = checkDependencyInstallScripts([
      { name: "native-helper", version: "2.1.0", license: "MIT", direct: false, hasInstallScript: true },
      { name: "plain-helper", version: "1.0.0", license: "MIT", direct: false, hasInstallScript: false },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-INSTALL-SCRIPT-DEP");
    expect(findings[0]?.evidence).toBe("native-helper@2.1.0");
  });

  it("does not flag a resolved tree with no lifecycle scripts", () => {
    expect(checkDependencyInstallScripts([
      { name: "plain-helper", version: "1.0.0", license: "MIT", direct: false, hasInstallScript: false },
    ])).toEqual([]);
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

  // #1067: a network error used to console.warn and return [] — a message on the operator's
  // terminal, and a deliverable in which the check is indistinguishable from "checked, clean".
  it("discloses SUP-SLOPSQUAT-00 naming the indeterminate packages on a network error", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    }) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react", "left-pad"], fetchImpl);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-SLOPSQUAT-00");
    expect(findings[0]?.confidence).toBe("N/A");
    expect(findings[0]?.title).toContain("2 dependencies");
    expect(findings[0]?.evidence).toContain("react, left-pad");
    expect(findings[0]?.evidence).toContain("ENOTFOUND");
  });

  it("does not flag on a non-404 error status (e.g. rate-limiting) but counts it as unassessed", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
    const findings = await checkSlopsquat(["react"], fetchImpl);
    expect(findings.map((f) => f.id)).toEqual(["SUP-SLOPSQUAT-00"]);
    expect(findings[0]?.evidence).toContain("HTTP 503");
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

  // A fully-resolved tree, so the coverage row only fires on a real gap. `direct: false` is the
  // #1213 case: a package reached only through the lockfile, which the pre-#1213 manifest-scoped
  // candidate list could never submit to the check.
  const scope = (candidates: LicenseCandidate[], over: Partial<LicenseScope> = {}): LicenseScope => ({
    rangeScopes: [],
    candidates,
    source: "package-lock.json",
    completeness: "complete",
    note: "Resolved dependency tree parsed from package-lock.json.",
    direct: candidates.filter((c) => c.direct).length,
    transitive: candidates.filter((c) => !c.direct).length,
    declaredFrom: { manifests: 1, source: "no workspace globs declared", unresolvedGlobs: [], unreadable: [] },
    ...over,
  });

  it("does not flag a dependency under a permissive license", async () => {
    const fetchImpl = packument({ license: "MIT" });
    const findings = await checkLicenseCompliance(scope([{ name: "react", version: "18.2.0", direct: true }]), { fetchImpl });
    expect(findings).toEqual([]);
  });

  it("flags a copyleft-licensed dependency at high precision with the SPDX id in evidence", async () => {
    const fetchImpl = packument({ license: "GPL-3.0" });
    const findings = await checkLicenseCompliance(scope([{ name: "gpl-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-COPYLEFT-gpl-lib@1.0.0");
    expect(findings[0]?.category).toBe("License compliance");
    expect(findings[0]?.evidence).toContain("GPL-3.0");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  // #1213 — the defect this issue is about. Measured on ATC 2026-07-27: no manifest in the
  // workspace declares `sharp`, yet `@img/sharp-*` appears 82 times in pnpm-lock.yaml, three of
  // them LGPL-3.0-or-later. Against the manifest-scoped candidate list those packages were never
  // submitted to the check, so an external scanner reported copyleft that Harvey did not.
  it("flags a copyleft package reached ONLY through the resolved tree, and says so", async () => {
    const findings = await checkLicenseCompliance(
      scope([{ name: "@img/sharp-libvips-linux-riscv64", version: "1.2.4", license: "LGPL-3.0-or-later", direct: false }]),
      { fetchImpl: packument({}) },
    );
    expect(findings.map((f) => f.id)).toEqual(["SUP-LICENSE-COPYLEFT-@img/sharp-libvips-linux-riscv64@1.2.4"]);
    expect(findings[0]?.evidence).toContain("reached only through the resolved dependency tree");
  });

  it("flags a missing license field as review-tier, never a silent skip", async () => {
    const fetchImpl = packument({});
    const findings = await checkLicenseCompliance(scope([{ name: "no-license-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-UNKNOWN-no-license-lib@1.0.0");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("flags npm's UNLICENSED marker the same as a missing license — never a permissive default", async () => {
    const fetchImpl = packument({ license: "UNLICENSED" });
    const findings = await checkLicenseCompliance(scope([{ name: "private-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("SUP-LICENSE-UNKNOWN-private-lib@1.0.0");
  });

  // #1079: the license data was already sitting in the lockfile Harvey had just parsed for the
  // SBOM (MEASURED 2026-07-27: 390 of 396 components in targets/calibration/package-lock.json carry
  // one), and this check was making one live registry request per dependency to fetch it again.
  it("answers from the lockfile without touching the registry, and says where the answer came from", async () => {
    const fetchImpl = packument({ license: "MIT" });
    const findings = await checkLicenseCompliance(scope([{ name: "gpl-lib", version: "1.0.0", license: "GPL-3.0", direct: true }]), { fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(findings[0]?.id).toBe("SUP-LICENSE-COPYLEFT-gpl-lib@1.0.0");
    expect(findings[0]?.evidence).toContain("the lockfile");
  });

  it("still queries the registry for a package the lockfile does not answer", async () => {
    const fetchImpl = packument({ license: "GPL-3.0" });
    const findings = await checkLicenseCompliance(scope([{ name: "gpl-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(findings[0]?.evidence).toContain("the npm registry");
  });

  // #1213: `/<name>/<version>` is that release's own manifest — the license of the version actually
  // installed, in a few KB rather than a whole packument (which for a popular package is megabytes,
  // and the candidate set is now the entire tree).
  it("asks the registry for the INSTALLED version's manifest when the tree resolved one", async () => {
    const fetchImpl = packument({ license: "GPL-3.0" });
    await checkLicenseCompliance(scope([{ name: "gpl-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledWith("https://registry.npmjs.org/gpl-lib/1.0.0");
  });

  // #1099: the top-level `license` field on a packument is a denormalized snapshot of the LATEST
  // publish, not necessarily the installed version's — a package that relicensed between releases
  // (permissive -> copyleft here) must be read from `versions[<v>]` for the version actually
  // installed, not the latest. Still reachable when a mirror does not serve the version route.
  it("reads the INSTALLED version's license from versions[<v>], not the top-level (latest) snapshot", async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      url.endsWith("/1.0.0")
        ? new Response("", { status: 404 }) // this mirror serves only the packument
        : new Response(JSON.stringify({ license: "GPL-3.0", versions: { "1.0.0": { license: "MIT" } } }), { status: 200 }),
    ) as unknown as typeof fetch;
    const findings = await checkLicenseCompliance(scope([{ name: "relicensed-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(findings).toEqual([]); // MIT (the installed version) never flags, unlike the latest GPL-3.0
  });

  it("falls back to the top-level snapshot when the packument has no versions[<v>] entry for the installed version", async () => {
    const fetchImpl = packument({ license: "GPL-3.0", versions: { "2.0.0": { license: "MIT" } } });
    const findings = await checkLicenseCompliance(scope([{ name: "gpl-lib", version: "1.0.0", direct: true }]), { fetchImpl });
    expect(findings[0]?.id).toBe("SUP-LICENSE-COPYLEFT-gpl-lib@1.0.0");
    expect(findings[0]?.evidence).toContain("GPL-3.0");
  });

  it("discloses SUP-LICENSE-00 naming the indeterminate packages on a network error (#1067)", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    }) as unknown as typeof fetch;
    const findings = await checkLicenseCompliance(scope([{ name: "react", version: "18.2.0", direct: true }]), { fetchImpl });
    expect(findings.map((f) => f.id)).toEqual(["SUP-LICENSE-00"]);
    expect(findings[0]?.confidence).toBe("N/A");
    expect(findings[0]?.evidence).toContain("react@18.2.0");
  });

  // #1213 — the coverage-guard half. A manifest-only inventory means the transitive tier was never
  // a candidate at all; before, that produced silence, which reads as a clean license bill.
  it("discloses SUP-LICENSE-00 for an incomplete inventory even when every candidate resolved", async () => {
    const findings = await checkLicenseCompliance(
      scope([{ name: "react", version: "^18.2.0", license: "MIT", direct: true }], {
        source: "package.json",
        completeness: "incomplete",
        note: "No lockfile was found.",
      }),
      { fetchImpl: packument({}) },
    );
    expect(findings.map((f) => f.id)).toEqual(["SUP-LICENSE-00"]);
    expect(findings[0]?.evidence).toContain("The dependency inventory itself is incomplete");
    expect(findings[0]?.fix).toContain("Commit a lockfile Harvey can parse");
  });

  // #1213: a pnpm/yarn lockfile records no license, so every candidate needs the network — for a
  // real monorepo that is thousands of requests. The cap bounds it; the row names what it cost.
  it("caps registry lookups, spends the budget on declared dependencies first, and names the rest", async () => {
    const fetchImpl = packument({ license: "MIT" });
    const candidates: LicenseCandidate[] = [
      ...Array.from({ length: 400 }, (_, i) => ({ name: `transitive-${i}`, version: "1.0.0", direct: false })),
      { name: "declared-lib", version: "1.0.0", direct: true },
    ];
    const findings = await checkLicenseCompliance(scope(candidates), { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(300);
    expect(fetchImpl).toHaveBeenNthCalledWith(1, "https://registry.npmjs.org/declared-lib/1.0.0");
    const coverage = findings.find((f) => f.id === "SUP-LICENSE-00");
    expect(coverage?.evidence).toContain("per-run registry-lookup cap of 300");
    expect(coverage?.title).toContain("101 packages");
  });

  // #1213: license classification off a lockfile needs no network, so unlike checkSlopsquat this
  // tier still runs under skipNetworkChecks — pinning off only the fallback keeps the dry-run
  // artifact deterministic while the copyleft detection stays exercised by the committed gate.
  it("classifies from the lockfile with skipRegistry, and discloses only what the lockfile could not answer", async () => {
    const fetchImpl = packument({ license: "MIT" });
    const findings = await checkLicenseCompliance(
      scope([
        { name: "gpl-lib", version: "1.0.0", license: "GPL-3.0", direct: false },
        { name: "silent-lib", version: "2.0.0", direct: true },
      ]),
      { fetchImpl, skipRegistry: true },
    );
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(findings.map((f) => f.id)).toEqual(["SUP-LICENSE-COPYLEFT-gpl-lib@1.0.0", "SUP-LICENSE-00"]);
    expect(findings[1]?.evidence).toContain("silent-lib@2.0.0");
    expect(findings[1]?.evidence).not.toContain("gpl-lib");
  });
});

// #1067: `skipNetworkChecks` (the deterministic dry-run harness) omitted both tiers with nothing
// said about it, so the committed artifact's silence read as two clean verdicts.
describe("deliberately skipped registry tier (#1067)", () => {
  it("states which packages went unassessed and that the skip was deliberate", () => {
    for (const finding of [slopsquatCoverageFinding(["react", "next"], NETWORK_SKIPPED_REASON), licenseCoverageFinding(["react", "next"], NETWORK_SKIPPED_REASON)]) {
      expect(finding.severity).toBe("Info");
      expect(finding.confidence).toBe("N/A");
      expect(finding.evidence).toContain("deliberately skipped");
      expect(finding.evidence).toContain("react, next");
      expect(finding.impact).toMatch(/NOT a (finding that every dependency exists|clean license bill)/);
    }
  });

  it("samples rather than dumps the name list once it is long", () => {
    const names = Array.from({ length: 30 }, (_, i) => `pkg-${i}`);
    const evidence = slopsquatCoverageFinding(names, NETWORK_SKIPPED_REASON).evidence;
    expect(evidence).toContain("pkg-0");
    expect(evidence).toContain("and 10 more");
    expect(evidence).not.toContain("pkg-29");
  });
});

// #1231 — the six checks #1213 left manifest-scoped, each with its own widening decision. These
// tests are about WHICH SET each one reads and what it says about the set it did not read; the
// detection logic itself is covered by the describes above.
describe("resolved-tree widening (#1231)", () => {
  const tree = { declared: new Set(["react"]), source: "pnpm-lock.yaml" };

  it("flags a typosquat that only the resolved tree reaches, and says it is not the client's to edit", () => {
    const [finding] = checkTyposquat(["react", "expres"], tree);
    expect(finding?.id).toBe("SUP-TYPO-expres");
    expect(finding?.location).toBe("pnpm-lock.yaml (expres)");
    expect(finding?.evidence).toContain("reached only through the resolved dependency tree");
    expect(finding?.fix).toContain("npm ls expres");
  });

  it("flags a known-malicious package reached transitively — the event-stream delivery shape", () => {
    const [finding] = checkKnownIoc(["react", "flatmap-stream"], "package.json", tree);
    expect(finding?.severity).toBe("Critical");
    expect(finding?.location).toBe("pnpm-lock.yaml (flatmap-stream)");
    expect(finding?.evidence).toContain("event-stream delivery shape");
  });

  // A caller with only a manifest passes no tree, and must get byte-identical wording to before —
  // the declared/transitive clause is additive, not a rewrite of every existing row.
  it("says nothing about the tree when the caller had no tree to give it", () => {
    const [typo] = checkTyposquat(["expres"]);
    expect(typo?.location).toBe("package.json");
    expect(typo?.evidence).not.toContain("resolved dependency tree");
    const [ioc] = checkKnownIoc(["flatmap-stream"]);
    expect(ioc?.location).toBe("package.json (flatmap-stream)");
    expect(ioc?.evidence).not.toContain("event-stream delivery shape");
  });

  it("attributes a range finding to the workspace member that declared it, not to the root", () => {
    const [finding] = checkUnpinnedDependencies([
      { manifest: "package.json", name: "zod", range: "3.22.0" },
      { manifest: "apps/web/package.json", name: "react", range: "^18.2.0" },
    ]);
    expect(finding?.evidence).toContain("react@^18.2.0 (apps/web/package.json)");
    expect(finding?.location).toBe("apps/web/package.json");
  });

  it("names the manifest count rather than one file when several members are flagged", () => {
    const [finding] = checkNonRegistryDependencies([
      { manifest: "apps/web/package.json", name: "left-pad", range: "git+https://example.com/left-pad.git" },
      { manifest: "apps/api/package.json", name: "local", range: "file:../local-pkg" },
    ]);
    expect(finding?.location).toBe("2 workspace manifests");
  });

  it("sees a workspace member's postinstall, which the root-only read never did", () => {
    const [finding] = checkInstallScripts([
      { label: "package.json", scripts: { build: "next build" } },
      { label: "apps/web/package.json", scripts: { postinstall: "node ./setup.js" } },
    ]);
    expect(finding?.evidence).toBe("apps/web/package.json → postinstall: node ./setup.js");
    expect(finding?.location).toBe("apps/web/package.json (scripts)");
  });
});

// #1231 — the registry existence check widened from the root manifest to every workspace member's,
// which is unbounded in principle. A silent truncation is the one outcome the cap must not have.
describe("checkSlopsquat registry-lookup cap (#1231)", () => {
  it("stops at the cap and names it, rather than truncating silently", async () => {
    const fetchImpl = vi.fn(async () => new Response("", { status: 200 })) as unknown as typeof fetch;
    const findings = await checkSlopsquat(Array.from({ length: 320 }, (_, i) => `pkg-${i}`), fetchImpl);
    expect(fetchImpl).toHaveBeenCalledTimes(300);
    const coverage = findings.find((f) => f.id === "SUP-SLOPSQUAT-00");
    expect(coverage?.title).toContain("did not run for 20 dependencies");
    expect(coverage?.evidence).toContain("cap of 300 packages was reached");
    expect(coverage?.evidence).toContain("pkg-300");
  });
});

// #1231/#1232 — the row that makes each check's scope legible in the deliverable. #1213's lesson is
// that a defensible scope decision recorded only in a comment is, from the client's side,
// indistinguishable from an oversight.
describe("supplyChainScopeFinding (SUP-SCOPE-00)", () => {
  const scope = (over: Partial<LicenseScope> = {}): LicenseScope => ({
    rangeScopes: [],
    candidates: [],
    source: "pnpm-lock.yaml",
    completeness: "complete",
    note: "",
    direct: 4,
    transitive: 391,
    declaredFrom: { manifests: 3, source: "pnpm-workspace.yaml", unresolvedGlobs: [], unreadable: [] },
    ...over,
  });
  const args = { license: scope(), treeNames: 395, declaredNames: 40, workspaceInternalNames: [], osvRan: true };

  it("names manifest bounds and the independently measured declared-range population", () => {
    const finding = supplyChainScopeFinding(args);
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.evidence).toContain("3 manifests (pnpm-workspace.yaml)");
    expect(finding.evidence).toContain("395 package names from pnpm-lock.yaml");
    expect(finding.evidence).toContain("SUP-UNPINNED and SUP-NON-REGISTRY");
    expect(finding.evidence).toContain("integrity hash");
    expect(finding.impact).toContain("NOT a verdict that the tree is clean");
  });

  it("keeps format-specific range facts in evidence and fix text and rejects the old blanket source claim", () => {
    const npm = parsePackageLock(JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^1.0.0" }, peerDependencies: { react: "^18.0.0" } } } })).ranges;
    const pnpm = parsePnpmLock("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      child:\n        specifier: ^1.0.0\n        version: 1.0.0\npackages:\n  child@1.0.0:\n").ranges;
    const yarn = parseYarnLock('child@^1.0.0:\n  version "1.0.0"\n').ranges;
    const forbidden = /tree cannot answer|never the range that was declared|range, which only a manifest carries|RANGE STRING, which only a manifest has|declared range, which no lockfile records/i;
    for (const range of [npm, pnpm, yarn]) {
      const finding = supplyChainScopeFinding({ ...args, license: scope({ source: range.source, rangeScopes: [range] }) });
      expect(finding.evidence).toContain(`${range.source} (${range.format} version ${range.sourceVersion}`);
      expect(finding.evidence).toContain(`${range.edges.length} admitted third-party range edges`);
      expect(`${finding.evidence} ${finding.fix}`).not.toMatch(forbidden);
      expect(finding.fix).toContain("npm v2/v3 declaration ranges are assessed");
    }
    expect(pnpm.detail).toContain("present but unread");
    expect(yarn.detail).toContain("selector range(s)");
    expect(readFileSync(new URL("./supply-chain.ts", import.meta.url), "utf8")).not.toMatch(forbidden);
  });

  it("moves the curated CVE table into the tree-wide set exactly when osv-scanner did not run", () => {
    expect(supplyChainScopeFinding(args).evidence).toContain("double-report");
    expect(supplyChainScopeFinding({ ...args, osvRan: false }).evidence).toContain("widened for this pass because osv-scanner did not run");
  });

  it("#1344: names the workspace-internal packages excluded from the registry-backed checks, and says nothing when there are none", () => {
    expect(supplyChainScopeFinding(args).evidence).not.toContain("workspace-internal");
    const finding = supplyChainScopeFinding({ ...args, workspaceInternalNames: ["@kit/ui", "@kit/supabase"] });
    expect(finding.evidence).toContain("2 workspace-internal package name(s) — @kit/ui, @kit/supabase");
    expect(finding.evidence).toContain("SUP-SLOPSQUAT-*");
  });

  it("discloses a workspace glob that resolved to nothing instead of a plausible-looking count", () => {
    const finding = supplyChainScopeFinding({
      ...args,
      license: scope({ declaredFrom: { manifests: 1, source: "pnpm-workspace.yaml", unresolvedGlobs: ["packages/*"], unreadable: ["apps/web/package.json"] } }),
    });
    expect(finding.evidence).toContain("matched no package.json");
    expect(finding.evidence).toContain("packages/*");
    expect(finding.evidence).toContain("could not be parsed");
  });
});
