# Per-rule CWE audit — the table #990 asked for and #1294 found missing (2026-07-31)

**Population, stated before auditing:** every `harvey-*` semgrep rule in
`src/scan/rules/semgrep/*.yml`. On `main` at `9305f21` that was **110** rules; this branch adds three
(`harvey-xpath-injection`, `harvey-ldap-injection`, `harvey-csv-formula-injection`, all from #1273),
so the population audited here is **113 rules carrying 56 distinct CWEs**. Re-derive it, do not quote
it: `git grep -oh "id: harvey-[a-z0-9-]*" -- src/scan/rules/semgrep | sort -u | wc -l`, and
`pnpm exec vitest run src/scan/rules/semgrep/owasp-mapping.test.ts` prints the rule and CWE counts on
every run.

**This is a CENSUS, not a sample.** #1294's finding — 3 mislabels in a sample of ~8 — is a sample
figure and is not repeated here; all 113 were read. The three it named are confirmed and fixed, and
reading the other 105 found **no fourth mislabel**, one secondary under-claim (`harvey-cookie-insecure`,
disclosed in its message rather than relabelled — see below), and two parent/child pairs that are
correct and are now recorded as such.

**What "why" means in the last column:** one line saying what the rule's MACHINERY determines, and
why no more specific CWE is justified by that machinery. Where a more specific CWE exists but the
pattern does not reach it, the column says so — that is the over-claim direction #1294's `harvey-static-iv`
finding was about.

## The three corrections

| rule | was | is | why |
|---|---|---|---|
| `harvey-insecure-random-token` | CWE-330 (parent) | **CWE-338** | Matches `Math.random()` inside a token/secret/otp-named function. Its file-neighbour `harvey-crypto-pseudorandombytes` matched `crypto.pseudoRandomBytes()` and carried the CHILD, CWE-338, for the same weakness at the same determinacy. Both are "a non-cryptographic PRNG produced a security-sensitive value". A02 mapping unchanged — CWE-338 is in A02's list. |
| `harvey-static-iv` | CWE-329 | **CWE-1204** | CWE-329 is CBC-RESTRICTED per MITRE ("Not Using a Random IV with CBC Mode"), but `$ALGO` is an unconstrained metavariable and the rule's own message says "CBC/CTR/GCM". The pattern does not determine the mode, so CWE-329 is not determined by it either. **Cost, stated:** CWE-1204 is absent from A02:2021's mapped-CWE list, so the rule loses its `owasp` field. A correct CWE with no bucket beats a wrong CWE with one. |
| `harvey-fail-open` | CWE-285 | **CWE-636** | Matches a `catch { return true }` / `catch { return { allowed: true } }` shape. Its own planted fixture is a RATE LIMITER, which is not an authorization weakness — what the pattern determines is a permissive default on error, whatever the check gates. **Cost, stated:** CWE-636 is in neither A01:2021's nor A04:2021's mapped-CWE list (MITRE places it under OWASP 2004 A7 / 2025 A10), so the rule loses its `owasp` field, and it joins `UNDISCRIMINATED` because the no-category bucket's members share nothing but their absence from OWASP's tables. |

Each OWASP claim above was VERIFIED 2026-07-31 against the published per-category "List of Mapped
CWEs" pages, and each MITRE name against that CWE's own `cwe.mitre.org` page.

## The structural half — a gate that can see the mistake

#1294's diagnosis was exact: the only CWE gate was CWE→OWASP-category, and **CWE-330 and CWE-338 both
map to A02, so swapping them was invisible**. Two things now cover it.

1. **`every parent/child CWE pair in simultaneous use is one that has been reasoned about`**
   (`owasp-mapping.test.ts`). `CWE_PARENT_OF` lists MITRE ChildOf relations among CWEs this rule set
   has used; a pair where BOTH ends are live must appear in `PARENT_CHILD_REASONED` with its reason.
   Asserted exactly in both directions, so a new pair fails as an under-specific label and a stale
   entry fails as a stale disclosure. **Negative control, run 2026-07-31:** restoring CWE-330 on
   `harvey-insecure-random-token` fails it, printing
   `CWE-330 -> CWE-338: parent on [harvey-insecure-random-token], child on [harvey-crypto-pseudorandombytes]`.
2. The two live pairs are legitimate and now say why: `CWE-200 -> CWE-540` (prod-sourcemaps uses the
   child because source-code inclusion is exactly what it proves; the five CWE-200 rules expose
   things that are not source code) and `CWE-668 -> CWE-200` (`public: true` proves a resource
   reached the wrong sphere and proves nothing about the contents, so claiming CWE-200 would
   over-claim).

The #1521 UNDISCRIMINATED census also moved, and the movement is the fixes working: it was 5 rules,
it is now **4**. `harvey-crypto-pseudorandombytes` and `harvey-static-iv` left it because the CWEs
they were confusable WITH (330, 329) are no longer in use at all; `harvey-fail-open` joined it for
the reason above.

## The secondary finding — `harvey-cookie-insecure`, disclosed not relabelled

#1294 is right that its `(?s)^[^;]*$` regex proves the cookie has NO attribute, so HttpOnly
(CWE-1004) and SameSite (CWE-1275) are as determined as Secure (CWE-614). It is not relabelled,
because there is no CWE for "no cookie attribute at all" and picking any one of the three would be
the same under-claim in a different direction. `Finding.cwe` is an array but `metadata.cwe[0]` is
what the gates and the report read, so carrying all three is an API-shape change rather than a label
fix. Instead the rule's `message` now states the bound: *"the CWE this finding carries names the
SECURE attribute only … the missing HttpOnly and SameSite are equally determined and are equally
your problem."* Making the CWE list genuinely multi-valued end-to-end is filed as a follow-up.

## The 113-row table

`mode` is `taint` (source→sink dataflow) or `pattern` (syntactic match). `tier` is `harveySeverity`.

### CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-lib-path-traversal` | taint/High | a LIBRARY-sourced value reaching `fs.readFile*`/`writeFile*`/`createReadStream` | The sink is a filesystem path built from data the code did not choose. CWE-22 is definitional; no child applies, because the pattern does not prove the traversal is symlink-based (CWE-59) or absolute (CWE-36). |
| `harvey-path-traversal` | taint/High | request input reaching the `fs` family, Supabase Storage keys, `res.sendFile`/`res.download` | Same weakness, request-sourced. The `..`-relative vs absolute distinction that would justify CWE-23/CWE-36 is not determined by the pattern. |
| `harvey-zip-slip` | pattern/High | `fs.writeFile*(path.join($D, $E.entryName), …)` | Zip-slip is a CWE-22 instance; MITRE has no separate archive-extraction child, so the parent is the most specific available. |

### CWE-78 — OS Command Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-command-injection` | taint/Critical | request input into `exec`/`execSync` | The sink runs a SHELL, so the metacharacter weakness is CWE-78, not its argv sibling CWE-88. |
| `harvey-lib-command-injection` | taint/Critical | library-sourced value into `exec`/`execSync`/`$CP.exec` | Same sink family, different source. |
| `harvey-spawn-shell-true` | pattern/Critical | `spawn`/`execFile` with `shell: true` | `shell: true` is what converts an argv API into a shell one, which is exactly the CWE-78/CWE-88 boundary. Without it these calls would be CWE-88's. |

### CWE-79 — Cross-site Scripting · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-dangerously-set-inner-html` | taint/High | request input into `dangerouslySetInnerHTML.__html` | Reflected XSS. MITRE's 79 children (80/81/83/87) name specific markup contexts the pattern does not determine. |
| `harvey-dangerously-set-inner-html-prop` | pattern/Medium | a non-literal, non-sanitized `__html` prop | Same sink; heuristic rather than taint-proven, which changes the tier, not the weakness. |
| `harvey-dangerously-set-inner-html-stored` | taint/High | a DB-read value into `__html` | Stored XSS; MITRE folds stored/reflected into CWE-79. |
| `harvey-document-write` | taint/High | `document.write($VAL)` | DOM-based XSS sink. |
| `harvey-dom-innerhtml` | taint/High | `$EL.innerHTML =` / `insertAdjacentHTML` | DOM-based XSS sink. |
| `harvey-href-js-url` | taint/Medium | a tainted `<a href={…}>` | `javascript:` URL XSS — CWE-83 ("Improper Neutralization of Script in Attributes") is tempting but names attribute-level filtering, which the pattern does not test. |
| `harvey-html-template-literal` | taint/High | request input interpolated into an HTML template literal handed to `res.send` | Server-rendered reflected XSS. |
| `harvey-jsx-prop-spread-injection` | taint/High | a tainted object spread into JSX props | The spread can set `dangerouslySetInnerHTML`; the weakness is the resulting script execution. |
| `harvey-open-url-sink` | taint/Medium | tainted `window.location`/`location.href` assignment | Shares the sink with CWE-601; carried as XSS because a `javascript:` value executes. `harvey-open-redirect` owns the server-side redirect half — the division is stated in `xss.yml`. |
| `harvey-set-attribute-xss` | taint/Medium | `setAttribute("href"/"src", tainted)` | Same URL-scheme execution. |
| `harvey-template-autoescape-off` | pattern/High | `Handlebars.compile(…, { noEscape: true })`, `Mustache.render(…, { escape: false })` | Disabling autoescaping is the missing-neutralization that CWE-79 is about. Not CWE-116: the escaping is not *incomplete*, it is switched off. |

### CWE-88 — Argument Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-argument-injection` | taint/High | tainted value in the ARGV ARRAY of `execFile`/`spawn` (focus `$ARGS`) | No shell is involved, so CWE-78 would be wrong; the weakness is a `--flag`-shaped argument reaching the invoked program. The `focus-metavariable: $ARGS` is what distinguishes it. |

### CWE-89 — SQL Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-sql-injection-rpc` | taint/Critical | tainted arg to `rpc("exec_sql"/"query"/…)` | The named RPCs execute SQL text; the tainted value is that text. |
| `harvey-sql-injection-template` | taint/Critical | tainted value in the SQL TEXT argument of `$C.query` | Focused on the text argument, not the bound-parameter array — which is what makes it CWE-89 rather than nothing. |

### CWE-90 — LDAP Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-ldap-injection` | taint/High | tainted value in the options/filter of `search`/`bind`/`compare`/`modify` inside a file requiring `ldapjs` | Definitional; there is no LDAP child CWE. #1273. |

### CWE-95 — Eval Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-code-injection-eval` | taint/Critical | tainted value into `eval`/`new Function` | CWE-95 is the child of CWE-94 that names the *dynamically evaluated code* case exactly, which is what these two sinks are. |
| `harvey-lib-code-injection` | taint/Critical | library-sourced value into `eval`/`new Function` | Same sink, different source. |

### CWE-113 — HTTP Request/Response Splitting · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-crlf-header-injection` | taint/Medium | tainted value in `res.setHeader($NAME, $VAL)` | The header VALUE is where CR/LF splits the response. CWE-93 (CRLF injection generally) is the parent; 113 names the HTTP-header instance. |

### CWE-116 — Improper Encoding or Escaping of Output · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-incomplete-sanitize` | pattern/Medium | `$S.replace($NEEDLE, $R)` with a non-global needle | The defect is that only the FIRST match is replaced — the escaping is incomplete rather than absent, which is precisely CWE-116 and not CWE-79 (the rule does not prove the value reaches HTML). |

### CWE-117 — Improper Output Neutralization for Logs · A09

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-log-injection` | taint/Low | request input into `console.*` | Log forging. Definitional; A09 is its OWASP home and it is the only CWE that category has in use here (SINGLETON_CATEGORY). |

### CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-internal-state-response` | pattern/Medium | `res.json({ … process.env … })` | What is exposed is process state to a client. CWE-497 (exposure of system data) is a near miss but is A01-unmapped and named for system-level data; 200 is the safer specific claim. |
| `harvey-missing-server-only` | pattern/Low | `process.env.$SECRET` in a file with no `"server-only"` marker | A boundary marker's ABSENCE, so what it proves is possible exposure to the browser bundle. |
| `harvey-nextconfig-env-secret` | pattern/Critical | `next.config` `env: { … process.env.X }` | Inlines a server secret into the client bundle. |
| `harvey-select-star-pii` | taint/Medium | a `select('*')` row reaching `res.json` | Over-broad projection returned to the caller. CWE-213 (intentional info exposure) would claim intent the pattern does not establish. |
| `harvey-server-client-leak` | pattern/Low | a server-fetched row spread into a client component's props | Same weakness at the RSC boundary. |

### CWE-209 — Generation of Error Message Containing Sensitive Information · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-db-error-disclosure` | pattern/Low | the caught DB `error` object serialised into a response | The error OBJECT reaching the client is definitionally CWE-209; CWE-200's generality would lose the "via an error message" fact the pattern proves. |
| `harvey-verbose-error` | pattern/Low | `$ERR.stack` / `$ERR.message` in a response body | Same, with the stack trace named. |

### CWE-235 — Improper Handling of Extra Parameters · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-hpp-query-cast` | pattern/Medium | `(req.query.$P as string).includes(…)` | A repeated query parameter arrives as an ARRAY; the cast back to `string` is the mishandling. CWE-235's own subject is extra/duplicated parameters. |

### CWE-252 — Unchecked Return Value · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-unchecked-mutation` | pattern/Medium | an awaited Supabase mutation whose result is never read | The value that would have carried the failure is discarded. |
| `harvey-void-async` | pattern/Medium | `void $F(...)` on an async call | `void` is the discard, explicitly. |
| `harvey-zero-row-update` | pattern/Medium | an `.update().eq()` chain with no `.select()` | A zero-row update returns success; without `.select()` nothing distinguishes it from a hit. |

### CWE-256 — Plaintext Storage of a Password · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-plaintext-password` | pattern/High | `insert/update({ password: req.body.$K })` with no hash call | The value is WRITTEN, so this is storage (256) rather than transmission (319). CWE-916 (weak password hash) needs a hash to exist. |

### CWE-295 — Improper Certificate Validation · A07

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-tls-verify-disabled` | pattern/Critical | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = "0"` | Turns the certificate check off outright. Not CWE-319: the channel is still encrypted, it is just unauthenticated. |

### CWE-319 — Cleartext Transmission of Sensitive Information · A02

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-insecure-ws-url` | pattern/High | `new WebSocket("ws://…")` | Unencrypted transport, named in the scheme. |
| `harvey-missing-hsts` | pattern/Medium | a headers block with no `Strict-Transport-Security` | HSTS's absence permits a cleartext downgrade; CWE-693 (protection mechanism failure) is the alternative and is less specific about WHAT is unprotected. |
| `harvey-pg-ssl-disabled` | pattern/High | `new Pool({ ssl: false })` against a pooler host | The DB connection carries credentials and rows in the clear. |

### CWE-321 — Use of Hard-coded Cryptographic Key · A02

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-hmac-hardcoded-key` | pattern/High | `createHmac($ALGO, "<literal>")` | The literal IS the key, so CWE-321 rather than the generic hard-coded-credentials CWE-798: what is embedded is cryptographic key material. |

### CWE-327 — Use of a Broken or Risky Cryptographic Algorithm · A02

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-crypto-createcipher` | pattern/High | `crypto.createCipher(...)` | The key-derivation-free legacy API. Not CWE-1204 — the IV is not the subject; the API itself is. |
| `harvey-gcm-no-authtaglength` | pattern/Medium | `createDecipheriv` with no `authTagLength` | Using an AEAD mode without pinning the tag length is a misuse of the algorithm. |
| `harvey-weak-cipher` | pattern/High | `createCipheriv("des"/"rc4"/…-ecb)` | The ALGORITHM string is the defect and is a literal here, which is what makes 327 determined (unlike `harvey-static-iv`, where it is not). |
| `harvey-weak-hash-security` | pattern/High | `createHash("md5"/"sha1")` in a security context | A broken hash. CWE-328 (weak hash) is a child but MITRE places the security-context use under 327's family; 327 is the label A02's list carries. |

### CWE-338 — Use of Cryptographically Weak PRNG · A02

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-crypto-pseudorandombytes` | pattern/High | `crypto.pseudoRandomBytes(...)` | Node's non-CSPRNG, named. |
| `harvey-insecure-random-token` | pattern/Medium | `Math.random()` inside a token/secret/otp-named function | **Corrected from CWE-330 by #1294.** JS's non-cryptographic PRNG producing a security-sensitive value is the same weakness as the row above, at the same determinacy. |

### CWE-346 — Origin Validation Error · A07

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-postmessage-no-origin` | pattern/Medium | a `message` listener with no `event.origin` check | The missing check IS origin validation. |
| `harvey-postmessage-wildcard` | pattern/Medium | `postMessage($DATA, "*")` | The target origin is unconstrained. |
| `harvey-serveractions-origin-wild` | pattern/High | `allowedOrigins: ["*"]` | Same weakness in Next's Server Actions config. Not CWE-942: that is the CORS *policy* header, a different mechanism. |

### CWE-347 — Improper Verification of Cryptographic Signature · A02

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-aead-decipher-no-final` | pattern/High | a decipher chain that never calls `.final()` | Skipping `final()` skips the AEAD tag check, which is a signature verification in the AEAD sense. |
| `harvey-jwt-decode-noverify` | pattern/High | `jwt.decode($T)` | `decode` never verifies. |
| `harvey-jwt-decode-render` | pattern/High | `jwtDecode(...)` used for a rendering/authz decision | Same, via the browser library. |
| `harvey-jwt-none-alg` | pattern/Critical | `algorithms: ["none"]` | Accepts an unsigned token. |
| `harvey-jwt-verify-noalg` | pattern/High | 2-arg `jwt.verify($T, $K)` | No algorithm allowlist → RS256/HS256 confusion, i.e. a signature that verifies against the wrong key type. |

### CWE-352 — Cross-Site Request Forgery · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-csrf-missing` | pattern/Medium | a state-changing handler with no CSRF token or Origin check | Definitional. |

### CWE-353 — Missing Support for Integrity Check · A08

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-missing-sri` | pattern/Medium | `<script src=…>` from a third-party origin with no `integrity` | The missing SRI attribute IS the missing integrity check. CWE-829 (untrusted functionality) describes the import; 353 describes the absent verification, which is what the pattern proves. |

### CWE-470 — Unsafe Reflection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-dynamic-dispatch` | taint/Medium | `$OBJ[$IDX](...)` with a tainted index | A member selected by a request-controlled key and immediately called — CWE-470's own subject. |

### CWE-489 — Active Debug Code · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-node-env-not-prod` | pattern/Low | `process.env.NODE_ENV = "development"` | Forces dev behaviour in a shipped build. |

### CWE-502 — Deserialization of Untrusted Data · A08

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-unsafe-deserialization` | taint/High | request input into `unserialize(...)` | Definitional. Its message already discloses that exploitability depends on the library in use. |

### CWE-522 — Insufficiently Protected Credentials · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-dangerously-allow-browser` | pattern/High | `dangerouslyAllowBrowser: true` | Ships an API key to the browser. Not CWE-798 — the key is not hard-coded, it is merely unprotected. |
| `harvey-token-in-webstorage` | pattern/Medium | `localStorage/sessionStorage.setItem` of a token-named key | Web Storage is readable by any injected script; the credential is stored unprotected. |

### CWE-524 — Use of Cache Containing Sensitive Information · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-sensitive-response-cached` | pattern/High | an authenticated response with a public `Cache-Control` | The cache is the exposure surface, which 524 names and CWE-200 does not. |

### CWE-540 — Inclusion of Sensitive Information in Source Code · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-prod-sourcemaps` | pattern/Medium | `productionBrowserSourceMaps: true` | Ships original source to the client. The CHILD of CWE-200 and correctly so — see `PARENT_CHILD_REASONED`. |

### CWE-598 — Use of HTTP Request With Sensitive Query String · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-secret-in-url-param` | pattern/Medium | a credential-looking name in a URL QUERY STRING | The query string is the leak channel (logs, Referer). Confusable with CWE-256 for the `password` param name — disclosed in `UNDISCRIMINATED`. |

### CWE-601 — Open Redirect · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-open-redirect` | taint/Medium | tainted value into `res.redirect`/`res.location`/`NextResponse.redirect`/`Location` header | The redirect TARGET is request-controlled. |

### CWE-602 — Client-Side Enforcement of Server-Side Security · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-client-trusted-role` | pattern/High | `req.body.isAdmin`-shaped privilege flags taken from the request | The privilege decision is made from a client-supplied value. Not CWE-863: no authorization check is present to be *incorrect*. |

### CWE-611 — XML External Entity Reference · A05

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-xxe` | pattern/High | `{ noent: true }` / `{ resolveEntities: true }` | Entity resolution turned on explicitly. |
| `harvey-xxe-parse` | taint/High | request input into `libxmljs.parseXml*` / `new DOMParser().parseFromString` | The parse of untrusted XML through an XXE-CAPABLE parser. Its message discloses both what it does not prove (that resolution is enabled) and the two parsers deliberately excluded (`sax`, `expat` — #1273). |

### CWE-613 — Insufficient Session Expiration · A07

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-jwt-ignore-exp` | pattern/High | `ignoreExpiration: true` | Expiry is switched off. |
| `harvey-jwt-sign-noexpiry` | pattern/Medium | `jwt.sign` with no `expiresIn` | No expiry is set. |
| `harvey-signed-url-ttl` | pattern/Medium | `createSignedUrl($P, <large N>)` | An over-long TTL on a capability URL. |

### CWE-614 — Sensitive Cookie Without 'Secure' Attribute · A05

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-cookie-insecure` | pattern/High | `setHeader("Set-Cookie", v)` where `v` has NO `;` — i.e. no attribute at all | **Under-claims by construction** (#1294 secondary): HttpOnly (CWE-1004) and SameSite (CWE-1275) are equally determined. Disclosed in the message rather than relabelled — see above. |
| `harvey-cookie-insecure-express` | pattern/High | `res.cookie(...)` without httpOnly AND secure AND sameSite | Same under-claim, same disclosure route. |

### CWE-636 — Not Failing Securely ('Failing Open') · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-fail-open` | pattern/Medium | `catch { return true }` / `catch { return { allowed: true } }` in a check function | **Corrected from CWE-285 by #1294.** The pattern determines a permissive default on error; it does not determine that the check gates authorization, and the rule's own fixture is a rate limiter. |

### CWE-639 — Authorization Bypass Through User-Controlled Key · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-idor-param` | taint/Medium | a request-supplied id used as the row key with no ownership comparison | IDOR/BOLA exactly. CWE-862/863 describe a missing or wrong check; 639 describes the user-controlled KEY, which is what the pattern proves. |

### CWE-643 — XPath Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-xpath-injection` | taint/High | tainted value in the EXPRESSION argument of the `xpath` package or DOM `evaluate`/`selectNodes` | Definitional; no child CWE exists. #1273. |

### CWE-668 — Exposure of Resource to Wrong Sphere · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-public-bucket` | pattern/High | `createBucket(..., { public: true })` | The PARENT of CWE-200 and correctly so: the flag proves the resource left its sphere and proves nothing about whether it holds sensitive data. See `PARENT_CHILD_REASONED`. |

### CWE-693 — Protection Mechanism Failure · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-csp-unsafe-inline` | pattern/Medium | a CSP header value containing `unsafe-inline` | The CSP exists but is defeated. Not CWE-79 — no script sink is proven. |
| `harvey-missing-nosniff` | pattern/Low | a headers block with no `X-Content-Type-Options` | A mitigation absent. |
| `harvey-vm-unsafe-sandbox` | pattern/High | `vm.runInNewContext`/`runInThisContext` with a non-literal | Node's `vm` is not a security sandbox; the protection mechanism does not hold. |

### CWE-770 — Allocation of Resources Without Limits or Throttling · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-body-parser-no-limit` | pattern/Medium | `express.json()`/`urlencoded()`/`raw()` with no `limit` | The missing bound is the weakness. |

### CWE-798 — Use of Hard-coded Credentials · A07

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-auth-admin-in-client` | pattern/Critical | `$C.auth.admin.$M(...)` in client-reachable code | An admin client can only exist here with an embedded service key. |
| `harvey-edgefn-secret-fallback` | pattern/Critical | `Deno.env.get(...) ?? "<literal>"` | The literal fallback IS a hard-coded secret. |
| `harvey-node-secret-fallback` | pattern/Medium | `process.env.$NAME \|\| "<literal>"` | Same shape in Node. |
| `harvey-service-role-in-client` | pattern/Critical | `process.env.(NEXT_PUBLIC_)?SUPABASE_SERVICE_ROLE_KEY` in client code | The service-role key reaching the browser. |
| `harvey-vite-service-role-in-client` | pattern/Critical | `import.meta.env.$K` naming a service key | Same, Vite's client-env mechanism. |

### CWE-829 — Inclusion of Functionality from Untrusted Control Sphere · A08

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-dynamic-require` | taint/High | `require($X)` with a tainted specifier | Which MODULE loads is request-controlled — 829's own subject, distinct from CWE-95 (which evaluates code the pattern supplies). |

### CWE-862 — Missing Authorization · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-cron-no-secret` | pattern/Medium | a cron route using `supabaseAdmin` with no `CRON_SECRET` check | No authority is checked at all → missing, not incorrect. |
| `harvey-isr-revalidate-nosecret` | pattern/Medium | `res.revalidate(req.query.$P)` with no secret check | Same. |
| `harvey-route-noauth` | pattern/Medium | a mutating route handler with no session/permission call | Same. |
| `harvey-server-action-noauth` | pattern/Medium | a Server Action with no session/permission call | Same. |

### CWE-863 — Incorrect Authorization · A01

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-authed-no-role-check` | pattern/High | a privileged handler that establishes IDENTITY but never checks ROLE | A check is present and insufficient → incorrect (863), not missing (862). The identity call in the pattern is what settles which of the two applies. |

### CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes · A08

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-mass-assignment` | taint/Medium | `insert/update({ ...$BODY })` | The whole request body spread into a write with no field allowlist. |
| `harvey-mass-assignment-bare` | pattern/Medium | `insert($BODY)`/`update($BODY)` | Same, without the spread. |
| `harvey-pg-mass-assignment` | pattern/Medium | `$FN($ID, req.body)` into a repo update | Same at the repository boundary. Not CWE-1321: the target is a DB row, not `Object.prototype`. |

### CWE-917 — Expression Language / Template Injection · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-template-injection` | taint/High | tainted TEMPLATE SOURCE into ejs/pug/nunjucks/handlebars/lodash compile-or-render | The user controls the template, not the data. CWE-1336 is the newer SSTI-specific id but is absent from A03's mapped-CWE list, so 917 keeps the OWASP field honest. |

### CWE-918 — Server-Side Request Forgery · A10

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-img-remotepatterns-wild` | pattern/High | a wildcard `hostname` in Next's `remotePatterns` | The image optimizer will fetch any host. |
| `harvey-ssrf-fetch` | taint/Medium | request input into `fetch`/`http(s).get`/`request`/`axios` | Definitional. |

### CWE-942 — Permissive Cross-domain Security Policy · A05

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-cors-reflected-origin` | pattern/High | the request `Origin` echoed into `Access-Control-Allow-Origin` with credentials | Reflecting the origin makes the policy universal. |
| `harvey-cors-reflected-origin-object` | taint/High | same, expressed as a headers object | Same weakness, object form. |
| `harvey-permissive-cors` | pattern/High | `"Access-Control-Allow-Origin": "*"` with credentials | The policy names every domain. |
| `harvey-permissive-cors-bare` | pattern/Low | the same wildcard without credentials | Same policy defect at a lower consequence — the tier moves, the weakness does not. |

### CWE-943 — Improper Neutralization of Special Elements in Data Query Logic · A03

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-nosql-injection` | taint/High | tainted value under a Mongo `$where`/`$regex`/`$ne`/`$gt` operator | Not CWE-89: the query language is not SQL. 943 is the query-logic parent that covers it. |
| `harvey-postgrest-filter-injection` | taint/Medium | tainted value into PostgREST `.or()`/`.filter()`/`.textSearch()` | The PostgREST filter grammar is the query logic being rewritten. |

### CWE-1021 — Improper Restriction of Rendered UI Layers or Frames · A04

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-missing-frame-options` | pattern/Medium | a headers block with no `X-Frame-Options` | Clickjacking; definitional. |

### CWE-1204 — Generation of Weak Initialization Vector (IV) · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-static-iv` | pattern/Medium | `createCipheriv($ALGO, $KEY, Buffer.from("<literal>"))` | **Corrected from CWE-329 by #1294.** `$ALGO` is unconstrained, so the CBC-restricted 329 is not determined; a literal IV at an unknown mode is 1204 exactly. |

### CWE-1236 — Formula Elements in a CSV File · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-csv-formula-injection` | taint/Medium | request input into a CSV/spreadsheet serializer with no formula-prefix neutralization | Definitional. #1273. |

### CWE-1321 — Prototype Pollution · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-prototype-pollution` | taint/High | tainted object into `merge`/`mergeWith`/`defaultsDeep` | The recursive-merge helpers are the path by which `__proto__` reaches `Object.prototype`. Not CWE-915: the target is the prototype, not a row's columns. |

### CWE-1333 — Inefficient Regular Expression Complexity · (no OWASP 2021 category)

| rule | mode/tier | what the pattern matches | why this CWE is the most specific justified |
|---|---|---|---|
| `harvey-redos` | pattern/Medium | `new RegExp($RE)` whose literal has a nested quantifier | The nested quantifier is the complexity. |
| `harvey-redos-literal` | pattern/Medium | the same shape written as a regex literal | Same. |

## What this audit did NOT settle

- **The `owasp` field is checked; a second or third CWE on a rule is not.** `metadata.cwe` is an
  array and every gate here reads `cwe[0]`. That is what made `harvey-cookie-insecure` a disclosure
  rather than a fix, and it is the follow-up this audit leaves open.
- **Rule↔CWE binding is vocabulary-based.** The #1521 check asks whether a rule's own body carries
  its CWE's vocabulary; four rules (`harvey-fail-open`, `harvey-public-bucket`,
  `harvey-prod-sourcemaps`, `harvey-secret-in-url-param`) would stay green under a swap to a named
  sibling, and three have no same-category sibling at all. Both populations are printed on every run
  and asserted exactly, so a drift fails the gate rather than passing unremarked.
- **`CWE_PARENT_OF` is not the CWE catalogue.** It lists ChildOf relations among CWEs this rule set
  has actually used. A mislabel involving a parent/child pair where neither end has ever appeared
  here is outside it.
