import { describe, expect, it } from "vitest";
import nextConfig from "./next.config.mjs";

describe("site TypeScript ESM resolution", () => {
  it("resolves emitted JavaScript specifiers to source TypeScript while preserving real files and existing aliases", () => {
    const config = { resolve: { extensionAlias: { ".wasm": [".wat", ".wasm"] } } };
    const webpack = nextConfig.webpack as (value: typeof config) => typeof config;

    expect(webpack(config)).toBe(config);
    expect(config.resolve.extensionAlias).toEqual({
      ".wasm": [".wat", ".wasm"],
      ".js": [".ts", ".js"],
      ".jsx": [".tsx", ".jsx"],
      ".mjs": [".mts", ".mjs"],
      ".cjs": [".cts", ".cjs"],
    });
  });
});
