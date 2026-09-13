// Offline process fixture: only the CLI's target inventory/advisory source is substituted.
// Git preparation, identity planning, cache readers, mechanical phases and scanner CLIs stay real.
import { registerHooks } from "node:module";
import { URL } from "node:url";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.endsWith("/src/cli/corpus-drift.ts")) {
      if (specifier === "../scan/external-corpus.js") return { url: new URL("./targets.mjs", import.meta.url).href, shortCircuit: true };
      if (specifier === "../corpus-advisory-snapshot.js") return { url: new URL("./snapshot.mjs", import.meta.url).href, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
