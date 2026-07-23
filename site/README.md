# harvey-qa.com

Marketing site for **Harvey** — codebase QA for Supabase + Next.js apps ("a senior QA
leader in a box"). A clean, static-first Next.js (App Router) app, intentionally dogfooded:
the site for a Next.js audit service should itself pass a Next.js audit.

Design and copy are ported 1:1 from the approved prototype in the main repo
(`../docs/gtm/content/homepage-prototype.html`). Strategy lives in `../docs/gtm/`.

## Run it locally

```bash
npm install
npm run dev
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

Set the same three as environment variables in the Vercel project before go-live. Without
them the form returns a clear "not set up yet" message rather than silently dropping leads.

## Build for production

```bash
npm run build
npm run start
```

## Deploy (needs operator action)

The site is ready to deploy to Vercel, but two one-time steps are yours:

1. **Authenticate Vercel** (the Claude Code Vercel plugin, or `npx vercel login`).
2. **Register the domain** `harvey-qa.com` (primary; optionally the no-hyphen
   `harveyqa.com` as a defensive redirect), then point it at the Vercel project.

Then `npx vercel --prod` (or connect the repo in the Vercel dashboard for auto-deploys).

## Structure

```
app/
  layout.tsx            Root layout — metadata, Organization/Service/FAQ JSON-LD, favicon,
                        Vercel Analytics, Search Console/Bing verification (env-driven), theme script
  page.tsx              The homepage (long-form landing; in-page anchors for its own sections)
  globals.css           All styles (hand-authored, theme-aware light/dark)
  opengraph-image.tsx   Dynamic 1200×630 OG image (next/og)
  sitemap.ts            /sitemap.xml (all routes)
  robots.ts             /robots.txt
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
  supabase-security-checker/     Free client-side RLS checker (browser-direct anon-read probe)
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
