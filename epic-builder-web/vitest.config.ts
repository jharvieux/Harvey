import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { defineConfig, type Plugin } from "vitest/config";

// The wrap layer and the src/epic-builder core import with explicit ".js" specifiers that resolve to
// ".ts" sources (NodeNext ESM). Vite/esbuild won't map ".js" -> ".ts" on its own, so rewrite the id
// when the ".ts" file exists. Mirrors the webpack `extensionAlias` in next.config.mjs.
function tsExtensionAlias(): Plugin {
  return {
    name: "ts-extension-alias",
    enforce: "pre",
    resolveId(source, importer) {
      if (!source.endsWith(".js") || !importer) return null;
      const abs = resolve(dirname(importer), source);
      const asTs = abs.replace(/\.js$/, ".ts");
      return existsSync(asTs) ? asTs : null;
    },
  };
}

export default defineConfig({
  plugins: [tsExtensionAlias()],
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
