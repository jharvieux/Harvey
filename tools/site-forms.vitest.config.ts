import { mergeConfig } from "vitest/config";
import base from "../vitest.config.js";

// Browser installation belongs to the CI browser step. Keep its actual Next/Chromium
// journeys explicit and serial, sharing the repository's timeout and event-loop controls.
export default mergeConfig(base, {
  test: { include: ["src/__tests__/site-browser-journeys.browser.ts"], fileParallelism: false },
});
