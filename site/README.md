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
  layout.tsx     Root layout — metadata, Organization/Service/FAQ JSON-LD, favicon
  page.tsx       The homepage (single-page site; nav links are in-page anchors)
  globals.css    All styles (hand-authored, theme-aware light/dark, ported from prototype)
  sitemap.ts     /sitemap.xml
  robots.ts      /robots.txt
public/
  favicon.svg    🔍 emoji favicon
  llms.txt       AEO: machine-readable description of Harvey for answer engines
```

## SEO / AEO already wired

- `Organization`, `WebSite`, `Service` (with the three price tiers), and `FAQPage`
  JSON-LD in `layout.tsx`.
- `llms.txt` at the root, sitemap, robots, per-page metadata, OpenGraph.
- Answer-first copy; semantic HTML.

## Known next steps (not yet built)

- **Free-scan intake form + Resend wiring.** The CTAs currently anchor to the "How it
  works" section. The launch plan (`../docs/gtm/05-website-plan.md`) calls for a
  simple form (email + repo URL) that emails the operator via Resend; the backend is
  manual at launch. This is the top priority before going live.
- **Separate pages** for Sample Report, Methodology, Blog/Research, Responsible
  Disclosure, and Data Handling (footer links currently point to `#`).
- **OG image** (`/opengraph-image`).
- Swap in real (anonymized) findings once the first engagements exist.

## Domain / naming

Brand: **Harvey**. Domain: **harvey-qa.com** (decided 2026-07-22 after harvey.review was
taken; the no-hyphen `harveyqa.com` is worth grabbing defensively). "Harvey" bare is
unwinnable in search (harvey.ai) — ranking comes from content, not the brand token. See
`../docs/gtm/02-positioning-messaging.md`.
