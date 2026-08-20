import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const directoryOrder = vi.hoisted(() => ({ reverse: false }));
vi.mock("./fs-walk.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./fs-walk.js")>();
  return {
    ...actual,
    readEntriesSafe(path: string) {
      const result = actual.readEntriesSafe(path);
      return directoryOrder.reverse ? { ...result, entries: [...result.entries].reverse() } : result;
    },
  };
});

import { discoverJourneyInventory } from "./journey-discovery.js";
import { serializeJourneyInventoryV1, validateJourneyInventoryV1 } from "./journey-schema.js";

describe("candidate journey discovery", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "harvey-journeys-"));
  });

  afterEach(() => {
    directoryOrder.reverse = false;
    rmSync(root, { recursive: true, force: true });
  });

  function write(path: string, contents: string | object): void {
    const absolute = join(root, path);
    mkdirSync(join(absolute, ".."), { recursive: true });
    writeFileSync(absolute, typeof contents === "string" ? contents : JSON.stringify(contents));
  }

  function manifest(path: string, contents: object): void {
    write(path === "." ? "package.json" : `${path}/package.json`, contents);
  }

  it("discovers all named adapters, projects, tests, routes, fixtures, page objects, scripts, and literal CI invocations", () => {
    manifest(".", {
      name: "journey-monorepo",
      packageManager: "pnpm@11.1.3",
      workspaces: ["apps/*"],
      scripts: { "ci:e2e": "pnpm --filter @acme/web qa:e2e && echo $ROOT_SECRET" },
    });
    write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");

    manifest("apps/web", { name: "@acme/web", scripts: {
      "qa:e2e": "pnpm run internal-alias && echo $SCRIPT_SECRET",
      unit: "playwright test && echo $BODY_MUST_NOT_SELECT_THIS",
    } });
    write("apps/web/playwright.config.ts", `export default defineConfig({
      testDir: "./e2e",
      projects: [{ name: "firefox" }, { name: "chromium" }],
    });
    throw new Error("TARGET_CONFIG_MUST_NOT_EXECUTE");`);
    write("apps/web/e2e/admin.spec.ts", `
      import { test } from "@playwright/test";
      test.describe("admin checkout", () => {
        test("owner completes purchase", async ({ page, adminSession }) => {
          await page.goto("https://shop.example/admin/checkout?token=ROUTE_SECRET");
        });
      });
    `);
    write("apps/web/e2e/fixtures.ts", `export const test = base.extend({ adminSession: async () => undefined });`);
    write("apps/web/e2e/pages/checkout.page.ts", "export class CheckoutPage {}\n");

    manifest("apps/cy", { name: "@acme/cy", scripts: { "test:cypress": "cypress run" } });
    write("apps/cy/cypress.config.ts", `export default defineConfig({ e2e: { specPattern: "cypress/e2e/**/*.cy.ts" } });`);
    write("apps/cy/cypress/e2e/auth/login.cy.ts", `describe("guest login", () => { it("signs in user", () => { cy.visit("/login?code=PRIVATE"); }); });`);

    manifest("apps/wdio", { name: "@acme/wdio", scripts: { "wdio:e2e": "wdio run ./wdio.conf.ts" } });
    write("apps/wdio/wdio.conf.ts", `export const config = {
      specs: ["./test/specs/**/*.e2e.ts"],
      suites: { smoke: ["./test/specs/smoke/*.e2e.ts"] },
      capabilities: [{ browserName: "chrome" }],
    };`);
    write("apps/wdio/test/specs/smoke/login.e2e.ts", `describe("member area", () => { it("opens dashboard", async () => { await browser.url("/dashboard"); }); });`);

    manifest("apps/browser", { name: "@acme/browser", scripts: { "test:browser": "vitest --browser" } });
    write("apps/browser/vitest.config.ts", `export default defineConfig({ test: {
      browser: { enabled: true, instances: [{ browser: "chromium" }] },
      include: ["browser/**/*.browser.test.ts"],
    } });`);
    write("apps/browser/browser/settings.browser.test.ts", `describe("authenticated user", () => { it("visits settings", async ({ page }) => { await page.goto("/settings"); }); });`);

    write(".github/workflows/e2e.yml", `
      name: browser checks
      jobs:
        e2e:
          steps:
            - run: pnpm run ci:e2e
              env:
                CLIENT_TOKEN: CI_SECRET_VALUE
            - run: pnpm exec playwright test
    `);

    const inventory = discoverJourneyInventory(root);
    expect(inventory.suites.map((suite) => suite.adapterId).sort()).toEqual([
      "cypress", "playwright", "vitest-browser", "webdriverio",
    ]);
    expect(inventory.projects.map((project) => project.name)).toEqual(expect.arrayContaining([
      "chrome", "chromium", "e2e", "firefox", "smoke",
    ]));
    expect(inventory.tests.map((test) => test.title)).toEqual(expect.arrayContaining([
      "owner completes purchase", "signs in user", "opens dashboard", "visits settings",
    ]));
    expect(inventory.tests.flatMap((test) => test.routes)).toEqual(expect.arrayContaining([
      "/admin/checkout", "/dashboard", "/login", "/settings",
    ]));
    expect(inventory.tests.find((test) => test.title === "owner completes purchase")).toMatchObject({
      criticality: "unconfirmed",
      fixtures: ["adminSession", "page"],
      personas: ["authenticated"],
      roles: ["admin", "owner"],
    });
    expect(inventory.fixtures.some((fixture) => fixture.path === "apps/web/e2e/fixtures.ts" && fixture.names.includes("adminSession"))).toBe(true);
    expect(inventory.pageObjects.some((pageObject) => pageObject.path === "apps/web/e2e/pages/checkout.page.ts" && pageObject.names.includes("CheckoutPage"))).toBe(true);
    expect(inventory.commands).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "package-script", scope: "full", bin: "pnpm", args: ["run", "qa:e2e"] }),
      expect.objectContaining({ kind: "package-script", scope: "focused", cwd: "apps/web", bin: "pnpm", args: ["run", "qa:e2e", "--", "e2e/admin.spec.ts"] }),
      expect.objectContaining({ kind: "ci-literal", scope: "ci", bin: "pnpm", args: ["run", "ci:e2e"] }),
      expect.objectContaining({ kind: "ci-literal", scope: "ci", bin: "pnpm", args: ["exec", "playwright", "test"] }),
    ]));
    expect(inventory.commands.some((command) => command.args.includes("unit"))).toBe(false);
    const serialized = serializeJourneyInventoryV1(inventory);
    expect(serialized).not.toContain("ROOT_SECRET");
    expect(serialized).not.toContain("SCRIPT_SECRET");
    expect(serialized).not.toContain("BODY_MUST_NOT_SELECT_THIS");
    expect(serialized).not.toContain("TARGET_CONFIG_MUST_NOT_EXECUTE");
    expect(serialized).not.toContain("ROUTE_SECRET");
    expect(serialized).not.toContain("CI_SECRET_VALUE");
    expect(validateJourneyInventoryV1(JSON.parse(serialized))).toEqual([]);

    directoryOrder.reverse = true;
    expect(discoverJourneyInventory(root)).toEqual(inventory);
  });

  it("counts generated, malformed, dynamic, unreadable, unsupported, missing-script, and zero-test states", () => {
    manifest(".", { name: "edge-cases", packageManager: "npm@11.5.1" });
    write("package-lock.json", "{}\n");
    write("playwright.generated.config.ts", "// @generated - do not edit\nexport default defineConfig({ testDir: './e2e' });\n");
    write("playwright.unreadable.config.ts", "export default defineConfig({ testDir: './private' });\n");
    chmodSync(join(root, "playwright.unreadable.config.ts"), 0o000);
    write("cypress.config.ts", "export default defineConfig({ e2e: { specPattern: [ });\n");
    write("wdio.conf.ts", "export const config = makeConfig(process.env);\n");
    write("vitest.config.ts", "export default defineConfig({ test: { browser: { enabled: true } } });\n");
    write("testcafe.config.ts", "export default {};\n");

    const inventory = discoverJourneyInventory(root);
    chmodSync(join(root, "playwright.unreadable.config.ts"), 0o600);
    const reasons = inventory.observations.filter((row) => row.status === "not-assessed").map((row) => row.reason);
    expect(reasons).toEqual(expect.arrayContaining([
      "dynamic-config", "generated-config", "malformed-config", "missing-script", "unreadable-config", "unsupported-framework", "zero-tests",
    ]));
    for (const row of inventory.observations.filter((entry) => entry.status === "not-assessed")) {
      expect(row.populationCount).toBeGreaterThan(0);
      expect(row.unitsExamined).toBe(0);
      expect(row.falsifier.length).toBeGreaterThan(12);
    }
  });

  it("represents a true no-suite target, and flips the Playwright row when a suite appears", () => {
    manifest(".", { name: "no-suite", packageManager: "yarn@1.22.22" });
    write("yarn.lock", "# yarn lockfile v1\n");
    write("vitest.config.ts", "// browser helpers are available to unit tests\nexport default { test: { environment: 'node' } };\n");
    const absent = discoverJourneyInventory(root);
    expect(absent.suites).toEqual([]);
    expect(absent.observations.filter((row) => row.status === "not-assessed" && row.reason === "absent-suite")).toHaveLength(4);

    write("playwright.config.ts", "export default { testDir: './e2e' };\n");
    write("e2e/smoke.spec.ts", "test('home loads', async ({ page }) => { await page.goto('/'); });\n");
    const present = discoverJourneyInventory(root);
    expect(present.suites.map((suite) => suite.adapterId)).toEqual(["playwright"]);
    expect(present.tests.map((test) => test.title)).toEqual(["home loads"]);
    expect(present.observations.some((row) => row.status === "not-assessed" && row.reason === "absent-suite" && row.adapterId === "playwright")).toBe(false);
  });

  it("rejects reordered populations, duplicate identities, extra schema fields, and promoted criticality", () => {
    manifest(".", { name: "schema", packageManager: "pnpm@11.1.3", scripts: { e2e: "playwright test" } });
    write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    write("playwright.config.ts", "export default { testDir: './e2e' };\n");
    write("e2e/a.spec.ts", "test('a', () => {});\n");
    const inventory = discoverJourneyInventory(root);

    const reordered = structuredClone(inventory);
    reordered.registry.configFamilyIds.reverse();
    expect(validateJourneyInventoryV1(reordered)).toContain("inventory.registry.configFamilyIds: values must be unique and sorted");

    const duplicated = structuredClone(inventory);
    duplicated.tests.push(structuredClone(duplicated.tests[0]!));
    expect(validateJourneyInventoryV1(duplicated)).toContain("inventory.tests: ids must be unique and sorted");

    const promoted = structuredClone(inventory) as unknown as { suites: { criticality: string }[] };
    promoted.suites[0]!.criticality = "critical";
    expect(validateJourneyInventoryV1(promoted)).toContain("inventory.suites[0].criticality: inferred journeys must remain unconfirmed");

    const extended = { ...structuredClone(inventory), secretDump: "must not be accepted" };
    expect(validateJourneyInventoryV1(extended)).toContain("inventory: unexpected field secretDump");
    expect(validateJourneyInventoryV1(inventory)).toEqual([]);
  });
});
