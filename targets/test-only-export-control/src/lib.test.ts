// Fixture only — vitest.config.ts excludes targets/**, so this file is never collected by the
// repo's own suite. It exists so knip sees a TEST referent for the planted exports and nothing else.

import { internallyUsed, testOnlyExport, type TestOnlyType } from "./lib.js";
import { neverCalledInProduction, ORPHAN_LIMIT } from "./orphan.js";

const t: TestOnlyType = { a: testOnlyExport() + internallyUsed() + neverCalledInProduction() + ORPHAN_LIMIT };
console.log(t);
