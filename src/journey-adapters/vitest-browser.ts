import type { JourneyAdapterDefinition } from "../journey-schema.js";

export const vitestBrowserJourneyAdapter = Object.freeze({
  id: "vitest-browser",
  order: 400,
  framework: "Vitest Browser",
  implementation: { file: "src/journey-adapters/vitest-browser.ts", exportName: "vitestBrowserJourneyAdapter" },
  configFamilies: [
    {
      id: "vitest-browser:config",
      pathPattern: "(^|/)vitest(?:\\.[A-Za-z0-9_-]+)?\\.config\\.[cm]?[jt]s$",
      contentMarkers: ["browser"],
      shape: "vitest-browser",
    },
    {
      id: "vitest-browser:projects",
      pathPattern: "(^|/)vitest\\.(projects|workspace)\\.[cm]?[jt]s$",
      contentMarkers: ["browser"],
      shape: "vitest-browser",
    },
    {
      id: "vitest-browser:vite-config",
      pathPattern: "(^|/)vite(?:\\.[A-Za-z0-9_-]+)?\\.config\\.[cm]?[jt]s$",
      contentMarkers: ["browser"],
      shape: "vitest-browser",
    },
  ],
  testPathPatterns: [
    "\\.browser\\.(spec|test)\\.[cm]?[jt]sx?$",
    "(^|/)(browser|e2e)/.*\\.(spec|test)\\.[cm]?[jt]sx?$",
  ],
  suiteCalls: ["describe", "suite"],
  testCalls: ["it", "specify", "test"],
  routeCalls: ["goto", "visit"],
  scriptNamePattern: "(^|[:_-])(browser|vitest-browser|e2e|acceptance|ui)([:_-]|$)",
  fixturePathPattern: "(^|/)(fixtures?|test-fixtures?|test-utils?)(/|\\.)",
  pageObjectPathPattern: "(^|/)(browser|e2e|tests?|specs?)/(.*/)?(page-objects?|pageobjects?|pages?)(/|$)|\\.page\\.[cm]?[jt]sx?$",
  defaultTestRoots: ["browser", "e2e", "test", "tests"],
  focusedArgs: (testPath: string): string[] => ["--run", testPath, "--browser"],
} satisfies JourneyAdapterDefinition);
