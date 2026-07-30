subscription-payments.client.json — a REAL webpack bundle-analyzer stats artifact (#1304).

Why it is here: parseBundleAnalyzerStats (src/detectors/bundle-stats.ts, shipped by #179) had
never seen one. Its only input was synthetic JSON its own test wrote, and between #862 and #1304
the module header claimed a live verification that actually belonged to parseBundleStats, a
different function. This capture makes the verification a gate instead of a memory.

HOW IT WAS PRODUCED — MEASURED 2026-07-28, reproducible:

  git init tmp && cd tmp
  git remote add origin https://github.com/vercel/nextjs-subscription-payments
  git fetch --depth 1 origin bdd0813206e47e6b218d42f15a7976c8a0d3c3eb && git checkout FETCH_HEAD
  pnpm add -D @next/bundle-analyzer@14.2.3          # pulls webpack-bundle-analyzer 4.10.x
  # next.config.js — the plugin has to be wired by hand, see the TRAP note below:
  #   const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');
  #   module.exports = { webpack(config, options) {
  #     if (!options.nextRuntime) config.plugins.push(new BundleAnalyzerPlugin({
  #       analyzerMode: 'disabled', generateStatsFile: true,
  #       statsFilename: '../analyze/client.json', statsOptions: { source: false },
  #     }));
  #     return config; } };
  ./node_modules/.bin/next build                     # writes analyze/client.json

That target is the pinned external-corpus entry `subscription-payments` (Next 14.2.3, webpack —
the bundler that emits this artifact at all). Placeholder Supabase/Stripe env values in .env.local
are enough; the stats file is written by the compile step, before typecheck.

TRAP: `@next/bundle-analyzer` does NOT expose `generateStatsFile`. MEASURED against 14.2.3 and the
current 16.2.12 — its whole option surface is { enabled, logLevel, openAnalyzer, analyzerMode },
and `analyzerMode: "json"` writes webpack-bundle-analyzer's treemap report (a top-level ARRAY of
{label, statSize, parsedSize, groups}), which is NOT the Stats.toJson() shape this detector parses.
The underlying BundleAnalyzerPlugin has to be wired into the target's own webpack hook.

WHAT WAS REDUCED, and why the capture is still real: the raw artifact is 38,604,063 bytes, which
does not belong in a repo. Every retained byte is verbatim webpack output — nothing was authored,
re-ordered or recomputed. Two mechanical reductions only:
  1. Per module, keep {type, moduleType, size, sizes, identifier, name, chunks, modules, id} and
     drop the rest (`reasons` alone is 12 MB, `issuerPath` 4.5 MB). `namedChunkGroups` is verbatim.
     Nested `modules` (webpack's concatenated-module children) are KEPT, recursively reduced the
     same way — dropping them loses whole packages from the attribution (ramda vanished when a
     `nestedModules: false` stats preset was tried).
  2. The absolute clone path is rewritten to `/repo`, so no machine-specific path is committed.
CONTROL: parseBundleAnalyzerStats over the 38 MB original and over this 556 KB capture produce
byte-identical M7B-04/05/06 findings. Recheck that before reducing anything further.
