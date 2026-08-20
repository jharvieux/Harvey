import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  JOURNEY_ADAPTER_REGISTRY,
  discoverJourneyAdapterImplementations,
  validateJourneyAdapterRegistry,
} from "./journey-adapter-registry.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary: string[] = [];

afterEach(() => {
  for (const directory of temporary.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function copiedAdapterRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-journey-registry-"));
  temporary.push(root);
  const directory = join(root, "src", "journey-adapters");
  mkdirSync(directory, { recursive: true });
  for (const adapter of JOURNEY_ADAPTER_REGISTRY) {
    writeFileSync(join(root, adapter.implementation.file), readFileSync(join(REPO_ROOT, adapter.implementation.file), "utf8"));
  }
  return root;
}

describe("journey adapter registry completeness", () => {
  it("matches every production adapter and config family discovered from source", () => {
    expect(validateJourneyAdapterRegistry(REPO_ROOT)).toEqual([]);
    expect(discoverJourneyAdapterImplementations(REPO_ROOT).map(({ id, configFamilyIds }) => ({ id, configFamilyIds }))).toEqual([
      { id: "cypress", configFamilyIds: ["cypress:config", "cypress:legacy-json"] },
      { id: "playwright", configFamilyIds: ["playwright:component-config", "playwright:config"] },
      { id: "vitest-browser", configFamilyIds: ["vitest-browser:config", "vitest-browser:projects", "vitest-browser:vite-config"] },
      { id: "webdriverio", configFamilyIds: ["webdriverio:config"] },
    ]);
  });

  it("fails when a discovered production adapter is removed from the registry, then passes when restored", () => {
    const withoutPlaywright = JOURNEY_ADAPTER_REGISTRY.filter((entry) => entry.id !== "playwright");
    expect(validateJourneyAdapterRegistry(REPO_ROOT, withoutPlaywright)).toEqual(expect.arrayContaining([
      expect.stringContaining("src/journey-adapters/playwright.ts#playwrightJourneyAdapter: discovered production journey adapter is unregistered"),
    ]));
    expect(validateJourneyAdapterRegistry(REPO_ROOT)).toEqual([]);
  });

  it("discovers a newly added adapter file instead of letting the registry hide it", () => {
    const root = copiedAdapterRoot();
    writeFileSync(join(root, "src", "journey-adapters", "ghost.ts"), `
      export const ghostJourneyAdapter = {
        id: "ghost",
        implementation: { file: "src/journey-adapters/ghost.ts", exportName: "ghostJourneyAdapter" },
        configFamilies: [{ id: "ghost:config" }],
      };
    `);
    expect(validateJourneyAdapterRegistry(root)).toContain(
      "src/journey-adapters/ghost.ts#ghostJourneyAdapter: discovered production journey adapter is unregistered",
    );
    rmSync(join(root, "src", "journey-adapters", "ghost.ts"));
    expect(validateJourneyAdapterRegistry(root)).toEqual([]);
  });

  it("fails when source declares a config family absent from the registered receipt", () => {
    const root = copiedAdapterRoot();
    const path = join(root, "src", "journey-adapters", "playwright.ts");
    const source = readFileSync(path, "utf8").replace(
      "configFamilies: [",
      'configFamilies: [{ id: "playwright:experimental-config", pathPattern: "experimental", shape: "playwright" },',
    );
    writeFileSync(path, source);
    expect(validateJourneyAdapterRegistry(root)).toEqual(expect.arrayContaining([
      expect.stringContaining("discovered config families differ from the registry"),
    ]));
  });
});
