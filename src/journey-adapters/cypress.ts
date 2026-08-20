import type { JourneyAdapterDefinition } from "../journey-schema.js";

export const cypressJourneyAdapter = Object.freeze({
  id: "cypress",
  order: 200,
  framework: "Cypress",
  implementation: { file: "src/journey-adapters/cypress.ts", exportName: "cypressJourneyAdapter" },
  configFamilies: [
    {
      id: "cypress:config",
      pathPattern: "(^|/)cypress\\.config\\.[cm]?[jt]s$",
      shape: "cypress",
    },
    {
      id: "cypress:legacy-json",
      pathPattern: "(^|/)cypress\\.json$",
      shape: "cypress",
    },
  ],
  testPathPatterns: [
    "(^|/)cypress/(e2e|integration)/.*\\.(cy|spec)\\.[cm]?[jt]sx?$",
    "\\.cy\\.[cm]?[jt]sx?$",
  ],
  suiteCalls: ["context", "describe"],
  testCalls: ["it", "specify"],
  routeCalls: ["visit"],
  scriptNamePattern: "(^|[:_-])(cypress|cy|e2e|acceptance|ui)([:_-]|$)",
  fixturePathPattern: "(^|/)cypress/(fixtures|support)(/|$)|(^|/)fixtures?(/|\\.)",
  pageObjectPathPattern: "(^|/)(cypress|e2e|tests?|specs?)/(.*/)?(page-objects?|pageobjects?|pages?)(/|$)|\\.page\\.[cm]?[jt]sx?$",
  defaultTestRoots: ["cypress/e2e", "cypress/integration"],
  focusedArgs: (testPath: string): string[] => ["--spec", testPath],
} satisfies JourneyAdapterDefinition);
