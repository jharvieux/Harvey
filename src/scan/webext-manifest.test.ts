import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkWebExtensionManifest } from "./webext-manifest.js";

describe("checkWebExtensionManifest", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function manifest(value: object): string {
    root = mkdtempSync(join(tmpdir(), "harvey-webext-"));
    const extension = join(root, "extension");
    mkdirSync(extension);
    writeFileSync(join(extension, "manifest.json"), JSON.stringify(value));
    return root;
  }

  it("flags broad host access combined with a sensitive capability", () => {
    const findings = checkWebExtensionManifest(manifest({
      manifest_version: 3,
      name: "fixture extension",
      permissions: ["cookies"],
      host_permissions: ["<all_urls>"],
    }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("WEBEXT-OVERBROAD-extension/manifest.json");
  });

  it("does not flag an extension scoped to one origin", () => {
    expect(checkWebExtensionManifest(manifest({
      manifest_version: 3,
      permissions: ["cookies"],
      host_permissions: ["https://app.example.com/*"],
    }))).toEqual([]);
  });
});
