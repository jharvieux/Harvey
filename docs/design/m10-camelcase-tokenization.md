# M10 severity ceiling on carbon — measured diagnosis and fix (#936)

**What this answers:** #936 observed that M10 tops out at Medium on carbon's 154-table HR/supplier/
customer ERP schema while a 5-table Stripe demo reaches High, and named two candidate causes —
aggregate-severity **dilution** or **dictionary coverage** — with the explicit instruction to
measure which is real before tuning either. This is that measurement plus the fix the evidence
implicated.

Every number below is from a run on **2026-07-24** against `crbnos/carbon @ 92e19c04` (the pinned
corpus commit), 859 Supabase migrations, `pnpm pii-classify --schema <carbon migrations>`.

## Diagnosis: dictionary coverage — specifically camelCase tokenization. NOT aggregation dilution.

### Hypothesis 1 (aggregation dilution) is FALSE — proven by reading and by measurement

`buildDataMap` (`tools/pii-classify.mjs`) scores a table by **summing the points of its distinct
infotypes** — `infotypes.reduce((sum, h) => sum + pointsFor(h), 0)`. There is no average and no
per-column denominator, so a wide table is not dragged down by its non-PII columns. Measured
confirmation after the fix: carbon's `company` table (~40 columns, mostly non-PII) scores **6.3 →
High**. Width did not dilute it. Dilution was never the mechanism.

### Hypothesis 2 (dictionary coverage) is TRUE — but the mechanism is tokenization, not missing infotypes

carbon's genuinely-sensitive columns were **not** absent from the dictionary. They were failing to
match because carbon uses **camelCase / quoted-identifier** column names (the Prisma/Drizzle
convention half the Supabase corpus uses) while every dictionary rule and every FP-exclusion anchors
on snake_case word boundaries `(^|_)…(_|$)`. A camelCase identifier presents no boundary, so
multi-word columns slipped through entirely. Measured on carbon's real `contact` table columns
before the fix:

| Column (carbon) | Before | Should be |
|---|---|---|
| `firstName`, `lastName`, `fullName` | NONE | NAME |
| `emailAddress` | NONE | EMAIL |
| `mobilePhone`, `homePhone`, `workPhone`, `phoneNumber` | NONE | PHONE |
| `addressLine1`, `postalCode` | NONE | ADDRESS |
| `dateOfBirth` | NONE | DOB |
| `taxId`, `vatNumber` | NONE | TAX_ID (SENSITIVE_PII) |
| `nationalId` | NONE | NATIONAL_ID (SENSITIVE_PII) |
| `socialSecurityNumber` | NONE | US_SSN (SENSITIVE_PII) |

Only bare single-token columns (`email`, `fax`, `city`) matched. This is not a mis-ranking — it is a
**silent under-count**: 60 PII-bearing tables were invisible to the classifier, which is worse than a
wrong severity because an absent row never appears in a tally.

## The fix

Normalise case boundaries to `_` before matching — a standard camel→snake transform with the acronym
pass (`taxId`→`tax_id`, `APIKey`→`api_key`) applied to both the column name and the table name in
`classifyColumn`. This makes a camelCase column behave **exactly** as its snake_case equivalent
would. Crucially the FP-exclusions gain the same boundary too, so `screenOrientation`→
`screen_orientation` (UI, suppressed), `raceId`→`race_id` (FK, suppressed), `isPinned`→`is_pinned`
(flag, suppressed), `emailCategory`→`email_category` (descriptor, suppressed) all stay excluded — the
fix cannot inflate the FP rate, it extends the existing snake_case behaviour to camelCase input.

## Before / after (measured, carbon @ 92e19c04)

| | Tables classified | High | Medium | Low |
|---|---|---|---|---|
| **Before** | 154 | 2 | 8 | 144 |
| **After** | 214 | 4 | 14 | 196 |

The two "Before" Highs were secret-store tables only (`printerRoute`, `oauthToken` — API key / auth
token). The ERP's HR/supplier/customer/contact PII genuinely topped out at Medium — because most of
it was invisible.

After the fix the model **discriminates**:

- **High** — `company` (6.3: business `taxId` + full address/phone/fax/email block), plus the three
  secret/oauth stores (`oauthClient.clientSecret` was itself a previously-invisible camelCase secret
  column, now surfaced).
- **Medium** — the personal/business contact clusters: `contact` (3.9: NAME+EMAIL+PHONE+FAX+notes),
  the billing-address tables, `user`, `supplier`, `customer`, `customerTax`/`supplierTax` (TAX_ID),
  `address`, `location`.
- **Low** — 196 lookup/reference tables carrying only an ambiguous `name` and/or a review-flag JSON
  container.

That is a real gradient where before there was "undifferentiated Medium×many."

## What was deliberately NOT changed (guarding against over-correction and target-tuning)

- **Severity thresholds and category weights are untouched.** The issue warned against tuning to make
  carbon reach High. The camelCase fix is the measured cause; the ceiling moved because real
  sensitive columns became visible, not because a knob was turned toward a target.
- **`contact` lands at Medium (3.9), one notch under High.** A full personal-identity dossier
  (name + email + three phones + fax + address + free-text notes) scoring just below High is a
  genuine judgment question about PII base-weighting, but changing `CATEGORY_POINTS.PII` would raise
  **every** small contact table in the corpus — the exact precision regression the over-correction
  guard exists to prevent. Left as an observation, not a change. (Follow-up candidate if the operator
  judges direct-identifier clusters should read High.)
- **Small snake_case schemas are provably unaffected.** `targets/calibration` is entirely snake_case;
  the normaliser is idempotent on it and the regenerated `dry-run/pii-data-map.json` is byte-identical
  (no diff). The 65-case `--selftest` and 91 unit tests (3 new camelCase blocks) pass unchanged.

## Corpus baseline consequence (follow-up, not applied here)

This change moves carbon's pinned M10 baseline in `src/scan/external-corpus.ts` from
`counted: 154, total: 154` to **214**, and the prose note ("highest severity produced anywhere in 154
tables is Medium") is now false — the ceiling is High and there are 214 tables. The baseline was left
UNTOUCHED here because a concurrent batch owns `external-corpus.ts` this sweep (corpus-drift #940).
The rebaseline to 214 with the measured note is a named follow-up.
