import { mergeConfig } from "vitest/config";
import base from "../vitest.config.js";

// Browser installation belongs to the CI browser step. Keep its actual Next/Chromium
// journeys explicit and serial, sharing the repository's timeout and event-loop controls.
const config = mergeConfig(base, {
  test: { include: ["src/__tests__/site-browser-journeys.browser.test.ts"], fileParallelism: false },
});

config.test!.exclude = config.test!.exclude?.filter(pattern => pattern !== "src/__tests__/site-browser-journeys.browser.test.ts");
export default config;
