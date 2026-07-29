// Asset-weight calibration (#170): fixture files are GENERATED at test runtime (a temp dir
// of Buffer-filled fakes) — committing multi-hundred-KB binaries to model "the repo has
// multi-hundred-KB binaries" would be self-inflicted repo bloat.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scanAssetWeight } from "./asset-weight.js";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "harvey-assets-"));
  mkdirSync(join(root, "public", "img"), { recursive: true });
  mkdirSync(join(root, "node_modules", "some-dep"), { recursive: true });
  writeFileSync(join(root, "public", "img", "hero.png"), Buffer.alloc(900 * 1024)); // fat image
  writeFileSync(join(root, "public", "img", "team.jpg"), Buffer.alloc(600 * 1024)); // fat image
  writeFileSync(join(root, "public", "img", "icon.png"), Buffer.alloc(12 * 1024)); // fine
  writeFileSync(join(root, "public", "promo.mp4"), Buffer.alloc(6 * 1024 * 1024)); // fat media
  writeFileSync(join(root, "node_modules", "some-dep", "big.png"), Buffer.alloc(2 * 1024 * 1024)); // excluded dir
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("oversized committed assets", () => {
  it("groups fat images into one worst-first finding and ignores small files and node_modules", () => {
    const findings = scanAssetWeight(root);
    const images = findings.find((f) => f.taxonomy === "M7 — Oversized committed images");
    expect(images).toBeDefined();
    expect(images?.title).toContain("2 committed images");
    expect(images?.location).toBe("public/img/hero.png"); // worst offender anchors the finding
    expect(images?.evidence).toContain("team.jpg");
    expect(images?.evidence).not.toContain("icon.png");
    expect(images?.evidence).not.toContain("node_modules");
    expect(images).toMatchObject({ severity: "Perf", confidence: "Review", id: "M7A-01" });
  });

  it("groups fat media separately", () => {
    const findings = scanAssetWeight(root);
    const media = findings.find((f) => f.taxonomy === "M7 — Oversized committed media");
    expect(media?.location).toBe("public/promo.mp4");
    expect(media?.id).toBe("M7A-02");
  });

  it("returns nothing when everything is under threshold", () => {
    expect(scanAssetWeight(root, { imageThresholdBytes: 1024 * 1024 * 10, mediaThresholdBytes: 1024 * 1024 * 10 })).toHaveLength(0);
  });
});

// #1480: an asset nothing references is never served, so the page-weight/LCP claim is false for
// it. MEASURED 2026-07-28 on proposit's public/Image.png (717 KB, referenced only from README.md).
describe("unreferenced assets are repo bloat, not page weight (#1480)", () => {
  it("splits referenced from unreferenced and gives each its own claim", () => {
    const sources = [{ text: 'import hero from "/img/hero.png";' }, { text: "const promo = '/promo.mp4';" }];
    const findings = scanAssetWeight(root, undefined, sources);
    const live = findings.find((f) => f.taxonomy === "M7 — Oversized committed images");
    const dead = findings.find((f) => f.taxonomy === "M7 — Unreferenced committed images");
    expect(live?.evidence).toContain("hero.png");
    expect(live?.evidence).not.toContain("team.jpg");
    expect(dead?.evidence).toContain("team.jpg");
    expect(dead?.impact).toContain("Repo bloat only");
    expect(dead?.impact).not.toContain("LCP");
    // The media file IS referenced, so it keeps the page-weight framing.
    expect(findings.find((f) => f.taxonomy === "M7 — Oversized committed media")?.evidence).toContain("promo.mp4");
    expect(findings.some((f) => f.taxonomy === "M7 — Unreferenced committed media")).toBe(false);
  });

  it("with no source set supplied, every asset keeps the page-weight framing rather than being guessed dead", () => {
    const findings = scanAssetWeight(root);
    expect(findings.some((f) => f.taxonomy.startsWith("M7 — Unreferenced"))).toBe(false);
    expect(findings.find((f) => f.taxonomy === "M7 — Oversized committed images")?.evidence).toContain("team.jpg");
  });
});
