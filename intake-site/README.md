# intake-site — Harvey client intake

Public site that documents what an engagement needs from a client and collects
intake + questionnaire answers (issue #32). Static `index.html` plus one
serverless function; no build step, no dependencies.

**Security posture:** the form has no fields for tokens or connection strings,
and the page tells clients not to paste them anywhere. Credentials are
exchanged out-of-band after kickoff via expiring share links (client's own
password manager preferred; Bitwarden Send as the default — decision recorded
on issue #33). Submissions are emailed to the operator
and stored nowhere.

## Deploy (Vercel)

1. Create a Vercel project with **root directory = `intake-site`** (zero config:
   static file + `api/` function are auto-detected).
2. Set environment variables:
   - `RESEND_API_KEY` — required; sending-only key is enough.
   - `INTAKE_TO` — optional, defaults to `jharvieux@gmail.com`.
   - `INTAKE_FROM` — optional, defaults to `Harvey Intake <onboarding@resend.dev>`.
     The default sender only delivers to the Resend account owner's address —
     verify a real domain in Resend before pointing `INTAKE_TO` anywhere else.

## Local preview

Open `index.html` directly for layout work. Submissions need the function, so
use `vercel dev` from this directory to exercise the full flow.

## Question set

The questionnaire mirrors the canonical kickoff auth questionnaire at
`docs/templates/auth-questionnaire.md` (issue #31) — that doc is the source of
truth. If the two ever diverge, update this form to match it, not the other
way around.
