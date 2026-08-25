import type { JourneyAdapterDefinition } from "../journey-schema.js";

export const playwrightJourneyAdapter = Object.freeze({
  id: "playwright",
  order: 100,
  framework: "Playwright",
  implementation: { file: "src/journey-adapters/playwright.ts", exportName: "playwrightJourneyAdapter" },
  dependencyNames: ["@playwright/test", "playwright", "playwright-core"],
  configFamilies: [
    {
      id: "playwright:script-only",
      pathPattern: "(?!)",
      shape: "playwright",
    },
    {
      id: "playwright:component-config",
      pathPattern: "(^|/)playwright-ct(?:\\.[A-Za-z0-9_-]+)?\\.config\\.[cm]?[jt]s$",
      shape: "playwright",
    },
    {
      id: "playwright:config",
      pathPattern: "(^|/)playwright(?:\\.[A-Za-z0-9_-]+)?\\.config\\.[cm]?[jt]s$",
      shape: "playwright",
    },
  ],
  testPathPatterns: [
    "(^|/)(e2e|tests?)(/.*)?\\.(spec|test)\\.[cm]?[jt]sx?$",
    "\\.(pw|playwright)\\.[cm]?[jt]sx?$",
  ],
  suiteCalls: ["describe", "test.describe"],
  testCalls: ["it", "specify", "test"],
  routeCalls: ["goto"],
  scriptNamePattern: "(^|[:_-])(e2e|playwright|pw|acceptance|ui)([:_-]|$)",
  fixturePathPattern: "(^|/)(fixtures?|test-fixtures?)(/|\\.)",
  pageObjectPathPattern: "(^|/)(e2e|tests?|specs?)/(.*/)?(page-objects?|pageobjects?|pages?)(/|$)|\\.page\\.[cm]?[jt]sx?$",
  defaultTestRoots: ["e2e", "test", "tests"],
  focusedArgs: (testPath: string): string[] => [testPath],
} satisfies JourneyAdapterDefinition);
