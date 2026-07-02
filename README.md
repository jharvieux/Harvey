# Harvey

External code-audit service: a 9-module security & codebase-health audit for multi-tenant Supabase/Next.js applications. Extracted from the ATC product repo (see epic [#2](https://github.com/jharvieux/Harvey/issues/2)).

## Layout

| Path | Contents |
|------|----------|
| `src/` | Scanner/toolkit code (findings schema + validation) |
| `docs/` | Audit-module spec, go/no-go analysis, scan briefs (`scan-extras.txt`, `quality-extras.txt`, `fp-rules.txt`), report skeleton, outreach templates |
| `docs/runbooks/` | Reference runbooks ported from ATC (anti-pattern taxonomy, slop detection, PR self-review, flaky-test policy) |
| `report-template/` | Findings JSON → HTML/PDF report renderer (Playwright) |
| `tools/` | Standalone audit tools (PII/PHI/PCI classifier) |

## Development

```bash
pnpm install
pnpm verify          # typecheck + lint + tests + knip
pnpm validate:findings report-template/findings.atc.json
```

Rendering a report additionally needs `pnpm exec playwright install chromium`, then:

```bash
node report-template/render.mjs <findings.json> [outDir]
```
# Harvey
