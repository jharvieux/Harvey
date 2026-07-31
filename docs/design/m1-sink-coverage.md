# M1 taint SINK coverage — the #985 expansion classes, re-derived (#1273)

**Date: 2026-07-31.** Every number below was produced by a run in this worktree on that date. The
figure this document re-derives came from an issue comment; re-run rather than quote this one too.

## Why this file exists

Eight sink-coverage gaps entered #985 as an operator comment two hours before it closed, and its
closing PR (#1005) addressed only the three classes in the original body. The comment was the ONLY
record of the per-class miss counts, and a comment on a closed issue is not a tracker. The counts
are preserved verbatim in the next section so the measurement survives the issue.

## Preserved verbatim — the per-class miss counts (#985 comment, 2026-07-24T18:43:42Z)

> **Expanded from the full true-miss sweep (all 62 categories, not just the low ones).** Additional
> taint SINK-coverage gaps where Harvey has the class but misses the shape — each is a real
> source→sink miss:
>
> - **open-redirect** — `res.redirect(data)` missed (34/50). `harvey-open-redirect` sinks don't
>   include the express `res.redirect` sink cleanly + the source gap (#984). Add
>   `res.redirect`/`res.location`.
> - **SSTI** — `res.send(nunjucks.renderString(data, {}))` (19/50, +11/50 el_injection). Add
>   `nunjucks.renderString`, `handlebars.compile`, `_.template`, `pug.render`, `ejs.render` with a
>   tainted template arg.
> - **prototype-pollution** — `_.merge({}, JSON.parse(data))` (50/50). Add lodash
>   `merge`/`mergeWith`/`set`/`setWith` and `Object.assign` recursive-merge sinks with tainted input.
> - **path-traversal / file-upload** — `fs.writeFileSync("/var/uploads/" + data, …)` (35/50
>   fileupload) and `fs.readFile`/`res.sendFile(taintedPath)` (42/50 pathtraver). Widen the
>   path-traversal sinks to `fs.readFile*`/`writeFile*`/`createReadStream`/`res.sendFile` with a
>   tainted path segment.
> - **XPath injection** — `xpath.select(expr, doc)` / `doc.evaluate(expr)` with tainted `expr`
>   (50/50 xpathi). New sink class.
> - **CRLF** — `harvey-crlf-header-injection` scores 0% despite existing; check its source/sink
>   shape against `res.setHeader(name, taintedValue)` (50/50 crlfinjection).
> - **(lower priority)** LDAP injection (`ldapClient.search(filter)`), CSV formula injection
>   (`=`/`+`/`@`-prefixed cell from tainted input) — new classes, rare in the Supabase/Next stack.
>
> All still taint-gated on a request source (so #984's source widening compounds with these). Each
> lands independently with paired pos/neg fixtures + `validate-calibration` pass.

Those counts are BenchProctor's synthetic corpus and are history, not a current measurement. The
class list is what this document re-derives.

## Method — the re-derivation

The inherited figure is "eight gaps". It was not re-used. Instead: one planted file per sink SHAPE,
each an Express handler carrying a request-sourced taint into the exact sink the comment names, run
through the real semgrep pass (`runSemgrep`, `src/scan/semgrep.ts`) over a git-initialised scratch
tree. Coverage is measured by RUNNING the scanner, never by grepping the rules — the repo's
`match`-key and fixture rules (#1190/#1191) exist because inspection gets this wrong.

**Scope control**: a `fetch(req.query.url)` file sits in the same directory. A fixture the scanner
never read reports zero exactly like one it scanned and missed, so a run in which the control does
not fire proves nothing about the rest of the table.

## Result — BEFORE (2026-07-31, on `main` at 9305f21)

| shape planted | rule that fired |
|---|---|
| `res.redirect(data)` | `harvey-open-redirect` |
| `res.location(data)` | **none** |
| `res.send(nunjucks.renderString(data, {}))` | **none** |
| `_.template(data)({})` | **none** |
| `handlebars.compile(data)` (lowercase binding) | **none** |
| `ejs.render(data, {})` | `harvey-template-injection` |
| `pug.render(data, {})` | `harvey-template-injection` |
| `_.merge({}, JSON.parse(data))` | `harvey-prototype-pollution` |
| `fs.writeFileSync("/var/uploads/" + data, …)` | `harvey-path-traversal` |
| `fs.readFile("/var/data/" + data, …)` | `harvey-path-traversal` |
| `res.sendFile(data)` | **none** |
| `xpath.select(expr, doc)` | **none** |
| `doc.evaluate(expr, …)` | **none** |
| `res.setHeader("X-Thing", data)` | `harvey-crlf-header-injection` |
| `ldapClient.search(base, { filter: "(uid=" + data + ")" }, …)` | **none** |
| CSV cell from `req.query` via `csv-stringify`/papaparse/json2csv | **none** |
| `sax.parser(...).write(data)` | **none** |
| `new expat.Parser().parse(data)` | **none** |
| SCOPE CONTROL: `fetch(req.query.url)` | `harvey-ssrf-fetch` ✓ |

**So the inherited "eight gaps" re-derives differently in BOTH directions.** Of the eight classes
the comment named, **four were already fully covered** by work that landed afterwards —
prototype-pollution and CRLF (#1224), the path-traversal `fs.*` sinks (#1220), and open-redirect's
`res.redirect` — and the residual was **eleven distinct sink SHAPES across six classes**, not eight
gaps. Three of those classes (XPath, LDAP, CSV formula) existed in no rule and in no issue anywhere
in the repo, exactly as #1273 recorded.

## Result — AFTER

Every shape above now fires except the two declined below. The changes:

- `harvey-open-redirect` (base.yml) gains `$RES.location($URL)` — express's `res.location` sets the
  same `Location` header `res.redirect` sets.
- `harvey-path-traversal` gains `$RES.sendFile($P)` / `$RES.download($P)`.
- `harvey-template-injection` gains `nunjucks.renderString`/`nunjucks.compile`, `_.template`/
  `lodash.template`, and the lowercase `handlebars.compile`/`hbs.compile` bindings. `nunjucks.render`
  is deliberately absent: its first argument is a template NAME resolved through the loader, not
  template source, so a tainted name is a path question rather than SSTI.
- **New:** `harvey-xpath-injection` (CWE-643, A03), `harvey-ldap-injection` (CWE-90, A03),
  `harvey-csv-formula-injection` (CWE-1236, no OWASP category — see below).

Each new rule ships a paired positive/negative in `targets/calibration/pages/api/` and its answer-key
row in `src/scan/calibration/b3-injection.entries.ts`. The negatives are the taint gate's boundary:
each calls the SAME sink with a server-owned expression/filter/record set, so a rule that matched the
sink CALL rather than its tainted argument fails loud. `validate-calibration`: GATE PASS, and the
rule↔corpus pairing census reads 113/113.

CWE-1236 carries a `cwe` with NO `owasp` field. VERIFIED 2026-07-31 against OWASP's own published
A03:2021 "List of Mapped CWEs" page: that list is CWE-20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90,
91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917 —
CWE-90 and CWE-643 are in it, CWE-1236 is not. Same posture as `harvey-redos`.

## Declined, with the reason — `sax` and `expat` as XXE sinks

#985's own body asked for "`sax`/`expat` parsers fed tainted input" under XXE and PR #1005 shipped
neither without saying so. They are declined here, and the reason is a property of the libraries, not
of our afternoon:

- **`sax`** resolves no DTD entities at all. Its README (fetched 2026-07-31): *"It's possible to
  define additional entities in XML by putting them in the DTD. This parser doesn't do anything with
  that"*, and *"A DTD-aware Thing"* is listed under **What This Is (probably) Not**. With no DTD
  processing there is no external entity to resolve, so a CWE-611 finding on a `sax` parse would be
  a false positive by construction.
- **`node-expat`** exposes no external-entity-reference handler, so nothing an application writes
  through that binding reaches an external entity either.

What is NOT covered by that reason, stated rather than left implied: feeding either parser untrusted
XML is still a resource-exhaustion question, which is a different weakness (CWE-776) from the one
`harvey-xxe-parse` reports. This is disclosure of a bound, not a claim that the input is safe.

The decline is stated where a client can read it — in `harvey-xxe-parse`'s own `message`, per the
#1317 rule that a rule declaring a bound must state that bound in its message.

## Reproducing

The probe is not committed; it is nineteen four-line Express handlers. Rebuild it by planting one
file per row of the BEFORE table under a git-initialised directory and calling `runSemgrep` on it —
or, cheaper, add a calibration pair for whatever shape you are asking about and run
`pnpm exec tsx src/cli/validate-calibration.ts`, which is where every claim in the AFTER section is
re-measured on every run.
