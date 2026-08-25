import type { JourneyAdapterDefinition } from "../journey-schema.js";

export const webdriverioJourneyAdapter = Object.freeze({
  id: "webdriverio",
  order: 300,
  framework: "WebdriverIO",
  implementation: { file: "src/journey-adapters/webdriverio.ts", exportName: "webdriverioJourneyAdapter" },
  dependencyNames: ["@wdio/cli", "webdriverio"],
  configFamilies: [
    {
      id: "webdriverio:script-only",
      pathPattern: "(?!)",
      shape: "webdriverio",
    },
    {
      id: "webdriverio:config",
      pathPattern: "(^|/)wdio(?:\\.[A-Za-z0-9_-]+)?\\.conf\\.[cm]?[jt]s$|(^|/)[A-Za-z0-9_-]+\\.wdio\\.conf\\.[cm]?[jt]s$",
      shape: "webdriverio",
    },
  ],
  testPathPatterns: [
    "(^|/)(e2e|tests?|specs?)/.*\\.(e2e|spec|test)\\.[cm]?[jt]sx?$",
    "\\.e2e\\.[cm]?[jt]sx?$",
  ],
  suiteCalls: ["context", "describe"],
  testCalls: ["it", "specify", "test"],
  routeCalls: ["url"],
  scriptNamePattern: "(^|[:_-])(webdriverio|wdio|e2e|acceptance|ui)([:_-]|$)",
  fixturePathPattern: "(^|/)(fixtures?|test-data|support)(/|\\.)",
  pageObjectPathPattern: "(^|/)(e2e|tests?|specs?)/(.*/)?(page-objects?|pageobjects?|pages?|screenplay)(/|$)|\\.page\\.[cm]?[jt]sx?$",
  defaultTestRoots: ["e2e", "spec", "specs", "test", "tests"],
  focusedArgs: (testPath: string): string[] => ["--spec", testPath],
} satisfies JourneyAdapterDefinition);
