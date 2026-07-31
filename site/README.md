# harvey-qa.com

Marketing site for **Harvey** — codebase QA for Supabase + Next.js apps ("a senior QA
leader in a box"). A clean, static-first Next.js (App Router) app, intentionally dogfooded:
the site for a Next.js audit service should itself pass a Next.js audit.

Design and copy are ported 1:1 from the approved prototype in the main repo
(`../docs/gtm/content/homepage-prototype.html`). Strategy lives in `../docs/gtm/`.

## Run it locally

Since #1597 this is a **pnpm workspace member of the repo root**, not a separate npm project:
there is no `site/package-lock.json`, and one `pnpm install` at the repo root provisions it.

```bash
cd ..            # repo root
pnpm install     # provisions site/ too
cd site
pnpm dev
```

Then open http://localhost:3000 — this is the real site (no claude.ai account needed).

## Environment variables (free-scan form)

The free-scan form (`app/api/scan`) emails you each request via Resend. Copy
`.env.example` → `.env.local` and set:

- `RESEND_API_KEY` — full-access key from https://resend.com/api-keys
- `SCAN_NOTIFY_TO` — your inbox (where new requests land)
- `RESEND_FROM` — optional; until `harvey-qa.com` is verified in Resend, the sandbox
  sender only delivers to your Resend account email (the operator notification still
  works; requester confirmations don't until the domain is verified).

`.env.example` lists **every** variable the site reads; `app/site-contract.test.ts` fails if
the code reads one that is missing from it.

Set the same names on the Vercel project before go-live. Without them the form returns a
clear "not set up yet" message rather than silently dropping leads — but it *is* rejecting
every lead, which is what happened in production for five days (#721/#1308):

```bash
cd ..    # repo root — the Vercel link lives here since #1597
printf '%s' "$RESEND_KEY" | vercel env add RESEND_API_KEY production
printf '%s' "$NOTIFY_INBOX" | vercel env add SCAN_NOTIFY_TO production
vercel env ls                      # confirm both are listed
vercel --prod                      # env vars only reach the site on the NEXT deploy
```

## Verify a deployment

```bash
# from the repo root, against production (default) or any preview/local URL
pnpm exec tsx src/cli/site-smoke.ts
pnpm exec tsx src/cli/site-smoke.ts --base http://localhost:3000
```

It fails loudly if the deployment serves fewer routes than `app/sitemap.ts` declares (i.e.
the deploy is behind `main`), or if `/api/scan` reports itself unconfigured. `GET /api/scan`
is a readiness probe returning `{"service":"scan-intake","configured":<bool>}` — 200 when
lead capture is live, 503 when its env vars are unset. It submits no lead and sends no mail.

## Build for production

```bash
cd site
pnpm build
pnpm start
```

## Deploy

**Deploy from the REPO ROOT, not from here.** MEASURED 2026-07-30 on the `harvey` Vercel project
(`prj_53NH7eOFAxXwoSKAMYO8Ye93qEer`): it has **no Git integration** — `link` is absent from the
project record, so nothing deploys on a push and every deploy is a manual CLI upload of the
directory you run it in. Since #1597 the project's **Root Directory is `site`** and the workspace
manifests it needs (`pnpm-lock.yaml`, `pnpm-workspace.yaml`, root `package.json`) live one level up,
so `cd site && vercel --prod` would upload a tree with no lockfile and fail.

```bash
cd ..                 # repo root — this is what gets uploaded
vercel deploy         # preview (SSO-protected; verifies the BUILD, not the content)
vercel deploy --prod  # production
pnpm exec tsx src/cli/site-smoke.ts   # verify LIVE — 6 checks against https://harvey-qa.com
```

`.vercelignore` (repo root) is an allowlist: only `site/`, `src/` and the three root manifests are
uploaded. A new top-level directory is excluded by default, so nothing starts shipping silently.

To undo the layout entirely, set the project's Root Directory back to empty:

```bash
vercel api -X PATCH "/v9/projects/prj_53NH7eOFAxXwoSKAMYO8Ye93qEer?teamId=team_MIXzwKpnQSfuj3hd9ZyWVPPh" \
  --input - <<< '{"rootDirectory":null}'
```

## Structure

```
app/
  layout.tsx            Root layout — metadata, Organization/Service/FAQ JSON-LD, favicon,
                        Vercel Analytics, Search Console/Bing verification (env-driven), theme script
  page.tsx              The homepage (long-form landing; in-page anchors for its own sections)
  globals.css           All styles (hand-authored, theme-aware light/dark)
  opengraph-image.tsx   Dynamic 1200×630 OG image (next/og)
  sitemap.ts            /sitemap.xml (all routes) — also the route CONTRACT the checks below use
  robots.ts             /robots.txt
  site-contract.test.ts Offline guard (#1308): sitemap ↔ page files ↔ internal links ↔ .env.example.
                        Runs in the main repo's `pnpm verify`. Also guards (#1597) that no
                        repo-root package shadows a version eslint-config-next pins
  components/
    SiteHeader.tsx      Shared nav + theme toggle (used by every page)
    SiteFooter.tsx      Shared footer (links to all real pages)
  the-audit/            Methodology: the ten modules, coverage ledger, live pen-test
  pricing/              Standalone pricing (size-band grid, tier matrix, FAQPage JSON-LD)
  sample-report/        Full sample report — SYNTHETIC demo data (sample-data.ts), never real client data
  responsible-disclosure/  Trust page — disclosure policy
  data-handling/        Trust page — repo/DB access, retention, deletion
  supabase-security-audit/       SEO service page (answer-first + FAQPage JSON-LD)
  supabase-security-checklist/   Interactive checklist (scanner-vs-live-test column)
  supabase-security-checker/     Free client-side RLS checker (browser-direct anon-read probe).
                                 Its write-probe logic lives at ../src/supabase-write-probe.ts
                                 since #1597 and is IMPORTED across what used to be a hard boundary
  multi-tenant-security-supabase/  Pillar guide (Article JSON-LD)
public/
  favicon.svg    🔍 emoji favicon
  llms.txt       AEO: machine-readable description of Harvey for answer engines
```

## SEO / AEO already wired

- `Organization`, `WebSite`, `Service` (with the three price tiers), and `FAQPage`
  JSON-LD in `layout.tsx`.
- `llms.txt` at the root, sitemap, robots, per-page metadata, OpenGraph.
- Answer-first copy; semantic HTML.

## Known next steps (not yet built — operator or follow-up)

- **Sample report: swap synthetic → real anonymized data**, and add the email-gated PDF
  download. The page ships now with clearly-labeled synthetic data for a fictional app.
- **Search Console + Bing ownership verification.** The meta-tag scaffold is wired to
  `NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION` / `NEXT_PUBLIC_BING_SITE_VERIFICATION`; the
  operator obtains the tokens and sets them in Vercel. Analytics + OG image are done.
- **RLS checker — deeper tiers.** The shipped tool is a browser-only anon-read probe.
  Authenticated cross-tenant / write / RPC probing and lead capture are a follow-up.
- **Trust pages need operator/legal review** before go-live, and the engagement/liability
  terms link lands once the LLM+terms work (#11) exists.
- **Blog/research** section is still to come.

## Domain / naming

Brand: **Harvey**. Domain: **harvey-qa.com** (decided 2026-07-22 after harvey.review was
taken; the no-hyphen `harveyqa.com` is worth grabbing defensively). "Harvey" bare is
unwinnable in search (harvey.ai) — ranking comes from content, not the brand token. See
`../docs/gtm/02-positioning-messaging.md`.
