# HarveyQA

HarveyQA is an independent software quality company that helps engineering teams find and fix the risks hidden in complex web applications. We combine automated analysis with expert review to give teams a practical, evidence-backed view of their codebase's security, reliability, performance, and maintainability.

## What we do

Our product is a comprehensive ten-module codebase audit built for modern, multi-tenant applications. It examines tenant isolation and application security, performs dynamic penetration testing, identifies risky code hotspots and duplication, detects dead or low-quality code, evaluates maintainability and performance, assesses test effectiveness, reviews Next.js application boundaries, and classifies sensitive data such as PII, PHI, and PCI data.

Each engagement turns the results into a prioritized, actionable report so teams know what is wrong, why it matters, and what to fix next. Harvey supports Supabase, Prisma/Postgres, and other common application data layers through detection-gated analysis.

- Website: [harvey-qa.com](https://harvey-qa.com)
- Email: [john@harvey-qa.com](mailto:john@harvey-qa.com)

This repository contains the HarveyQA audit engine, supporting tools, audit specifications, and report renderer. The project was originally extracted from the ATC product repository; development is tracked in [epic #2](https://github.com/jharvieux/Harvey/issues/2).

## Layout

| Path | Contents |
|------|----------|
| `src/` | Scanner/toolkit code (findings schema + validation) |
| `briefs/` | Audit-module specification and scanner briefs |
| `docs/` | Product, design, runbook, and go-to-market documentation |
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
