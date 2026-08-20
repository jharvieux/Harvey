import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "./discover-journeys.js";
import { parseJourneyInventoryV1 } from "../journey-schema.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/discover-journeys.ts";
const temporary: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporary.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function target(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-journey-cli-"));
  temporary.push(root);
  writeFileSync(join(root, "package.json"), JSON.stringify({
    name: "cli-target",
    packageManager: "pnpm@11.1.3",
    scripts: { "verify:e2e": "playwright test && echo $CLI_SCRIPT_SECRET" },
  }));
  writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  writeFileSync(join(root, "playwright.config.ts"), "export default { testDir: './e2e', projects: [{ name: 'chromium' }] };\n");
  mkdirSync(join(root, "e2e"));
  writeFileSync(join(root, "e2e", "login.spec.ts"), "test('user logs in', async ({ page }) => { await page.goto('/login?token=CLI_ROUTE_SECRET'); });\n");
  return root;
}

describe("discover-journeys CLI", () => {
  it("writes one normalized JourneyInventoryV1 artifact without leaking target shell bodies or URL queries", () => {
    const root = target();
    const output = join(root, "journeys.json");
    expect(() => main(["node", CLI, root, "--out", output])).not.toThrow();
    const serialized = readFileSync(output, "utf8");
    const inventory = parseJourneyInventoryV1(serialized);
    expect(inventory.schemaVersion).toBe(1);
    expect(inventory.tests.map((test) => test.title)).toEqual(["user logs in"]);
    expect(inventory.commands).toEqual(expect.arrayContaining([
      expect.objectContaining({ scope: "full", bin: "pnpm", args: ["run", "verify:e2e"] }),
      expect.objectContaining({ scope: "focused", bin: "pnpm", args: ["run", "verify:e2e", "--", "e2e/login.spec.ts"] }),
    ]));
    expect(serialized).not.toContain("CLI_SCRIPT_SECRET");
    expect(serialized).not.toContain("CLI_ROUTE_SECRET");
  });

  it("prints the same artifact to stdout and fails loud on an unknown flag", () => {
    const root = target();
    let stdout = "";
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => { stdout += String(chunk); return true; });
    main(["node", CLI, "--target", root]);
    expect(parseJourneyInventoryV1(stdout).tests).toHaveLength(1);

    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((message) => { errors.push(String(message)); });
    vi.spyOn(process, "exit").mockImplementation(((code?: string | number | null) => { throw new Error(`exit:${String(code)}`); }) as never);
    expect(() => main(["node", CLI, "--targte", root])).toThrow("exit:2");
    expect(errors.join("\n")).toContain("Unrecognized flag: --targte");
  });

  it("keeps sync-stdio first and has a zero-spawn, zero-target-import production seam", () => {
    const cli = readFileSync(join(REPO_ROOT, CLI), "utf8");
    expect(cli.split("\n")[0]).toBe('import "./sync-stdio.js";');
    const files = [
      "src/journey-discovery.ts",
      "src/journey-adapter-registry.ts",
      "src/journey-schema.ts",
      "src/journey-adapters/playwright.ts",
      "src/journey-adapters/cypress.ts",
      "src/journey-adapters/webdriverio.ts",
      "src/journey-adapters/vitest-browser.ts",
      CLI,
    ];
    const production = files.map((path) => readFileSync(join(REPO_ROOT, path), "utf8")).join("\n");
    expect(production).not.toContain("node:child_process");
    expect(production).not.toMatch(/\b(?:execFile|execSync|spawn|fork)\s*\(/);
    expect(production).not.toMatch(/\bimport\s*\(/);
  });
});
