# Anti-patterns (D-091)

Recurring bug-class patterns identified in the 2026-05-26 Greptile audit. Each pattern has a preventive mechanism (ESLint rule, slop-check pattern, doctrine line, or test probe).

**Provenance**: this is Harvey's vendored copy of ATC's canonical D-091 catalog. Items 1–20 and 22–29 are vendored (near-verbatim, ATC codebase paths retained as illustrative examples) from ATC's `docs/runbooks/anti-patterns.md`; item 21 is Harvey-specific (see below). Last synced from ATC @ `04a565d` (2026-07-19), which carries **28** classes — Harvey now covers **all** ATC classes **1–28** (Harvey's +1 offset from item 22 onward: ATC 21–28 = Harvey 22–29). Harvey total = **29** (28 vendored + 1 Harvey-specific). Run `pnpm brief-freshness <target-repo>` to diff this vendored copy against a target that ships its own D-091 catalog.

## 1. Stub-shaped code

**Symptom**: a function's signature or shape suggests one behavior; the body silently delivers a subset.

**Examples**:
- `getPublicKey(kid)` accepts a kid arg but ignores it and returns the same PEM
- `withPlatformAdminAudit` "supports" nested calls but skips the friction gate when nested
- Custom JS `timingSafeEqual` looks constant-time but JIT can break the guarantee
- `else if (Object.keys(updates).length > 0)` branch that is always-false dead code

**Why slips through review**: code compiles, type-checks, and passes happy-path tests because the stub matches the right shape. Detection requires reading parameters vs body.

**Prevention**:
- **Doctrine** (CLAUDE.md): "If a function takes a parameter, every parameter must affect output. Stub args are slop."
- **Slop-check**: `unused-parameter-detector` — flag function parameters never referenced in the body.
- **Doctrine**: when reviewing, ask "could this function be replaced with one that has fewer parameters and identical behavior?" If yes, the extras are stubs.

## 2. Fail-open when the enforcement layer goes down

**Symptom**: a defense-in-depth layer returns "permit" when it can't run (Redis down, DB error, secret unset).

**Examples**:
- Rate limit returns `{ allowed: true }` when Redis is unreachable
- Stripe webhook returns 200 even when DB update silently fails — Stripe stops retrying
- Missing `stripe-signature` header passed as empty string to constructEvent

**Why slips through**: the failure mode correlates with broader infra incidents that aren't covered in normal testing.

**Prevention**:
- **ESLint** (opt-in): `atc/no-fail-open-on-resource-error` — flag catch blocks returning `{ allowed: true }`, `{ ok: true }`, or 200 without re-throw/log.
- **Doctrine** (CLAUDE.md): "Fail-closed by default. When an enforcement layer is unreachable, the answer is denial, not permission. Failing open at the worst moment is the worst failure mode."
- **Probe**: error-injection probe that fires DB errors mid-handler and asserts the response is 500 (not 200).

## 3. Unchecked Supabase mutations

**Symptom**: `await db.from(x).update(y).eq(z)` is awaited but the `{ data, error }` tuple is discarded. Supabase JS v2 does NOT throw on DB errors — silent failure is the default.

**Examples**: 113 sites across the codebase. Most concentrated in `apps/main/src/app/api/forums/*`, `apps/main/src/app/api/tenant/*`, and `apps/main/src/lib/stripe/webhook-handler.ts`.

**Why slips through**: every happy-path test passes; the silent-failure path only triggers under DB-level errors not present in dev.

**Prevention**:
- **ESLint**: `atc/no-unchecked-supabase-mutation` — flag any `await ...update/insert/delete/upsert(...)` whose result isn't destructured to check `error`. Ships at `warn` initially; flip to `error` after the existing 113-site cleanup.
- **Doctrine**: "Supabase JS v2 doesn't throw. Every mutation must destructure `{ error }` and return non-200 on truthy error."

## 4. Credentials in URL query strings

**Symptom**: external API call constructs the URL with `?token=...` or `?api_key=...` instead of using an `Authorization: Bearer` header.

**Examples**:
- `apify-pricing-adapter.ts:226` — Apify token in URL
- `cruisemapper-actor.ts:102` — same pattern

**Why slips through**: the request succeeds; the leak surface (proxy logs, error messages embedding URL) is invisible until reviewed.

**Prevention**:
- **ESLint**: `atc/no-credentials-in-url` — flag template-literal URL construction containing `?token=`, `?api_key=`, `?secret=`, `?password=`.
- **Doctrine**: "External API credentials always go in headers, never query strings. Headers are routinely scrubbed from access logs; URLs are not."

## 5. App-layer scope check without DB-layer enforcement

**Symptom**: a tenant-scoped query bypasses RLS (via service-role client) and relies on a single application-layer scope check.

**Examples**:
- `rag_media_assets` query in `/api/retrieve` — service-role + app-layer scope check, no SQL `WHERE tenant_id = ?`
- `assert-platform-admin.ts` and `factories.ts` use service-role without an explicit ESLint exemption
- `feedback` endpoint inserts rows without a `tenant_id` column at all

**Why slips through**: the app-layer check looks complete in the code. The fact that RLS isn't a second layer requires reading the client type.

**Prevention**:
- **Doctrine**: "Every tenant-scoped query should have BOTH an app-layer filter AND a DB-layer constraint (RLS via tenantClient, or an explicit `.eq("tenant_id", ...)` on the service-role query). If only one exists, the code MUST comment why."
- **Probe**: extend `cross-tenant-probe` to fire each known service-role endpoint with a wrong-tenant body and assert the response is rejected before DB write.

## 6. TOCTOU / stale-read in budget or limit gates

**Symptom**: a gate reads a quota value, then the caller consumes that quota across multiple operations without re-reading.

**Examples**:
- Apify monthly budget read once at run start, not re-checked between 9 line batches
- `estimated_skipped` rows write phantom spend that inflates the cap
- Forensics access counter non-atomic read-modify-write (related class)

**Why slips through**: sequential single-run tests pass. Catching requires concurrent or multi-batch test cases.

**Prevention**:
- **Doctrine**: "Quota gates must re-read between consuming operations. If two crons can overlap, the gate must be atomic at the DB level (advisory lock or transactional reserve-row)."
- **Slop-check** (opt-in): `stale-budget-read-detector` — flag patterns where a value is read once outside a loop, and the loop body consumes that resource without re-reading.
- **Probe**: error-injection probe also runs a "concurrent execution" mode that fires the same cron twice and asserts the budget cap is respected.

---

## Round-2 patterns (post second Greptile audit, 2026-05-26)

### 7. Zero-row update returns `error: null`

**Symptom**: CAS-style lock pattern — `.update({status: 'X'}).eq("id", id).eq("status", 'Y')` — silently no-ops when the row's current status isn't `'Y'`. Supabase JS does NOT distinguish "matched 0 rows" from "succeeded with N=0 affected rows" — both return `{ error: null }`.

**Codebase instances (3 found)**:
- `apps/main/src/inngest/payouts-execute-transfer.ts:75-76` (Greptile-flagged — real money)
- `apps/main/src/inngest/evaluate-price-watches.ts:56-57` (NEW)
- `apps/main/src/inngest/tenant-on-terminated.ts:52-53` (NEW)

**Why slips through**: tests with the row in the expected state pass; tests with the row in unexpected state see no error and assume the update happened.

**Prevention**:
- **Doctrine** (CLAUDE.md): "CAS-style status-guarded updates MUST chain `.select('id')` to get the affected-row array, then assert `result.length === 1`."
- **Code review**: any `.update(...).eq("status", literal)` triggers checklist item.
- **ESLint**: feasible but heuristic — flag any `update(...)` followed by 2+ `.eq()` calls without a `.select()` on the chain.

### 8. `void`-prefixed async in serverless functions

**Symptom**: `void someAsyncFn(...)` fire-and-forget. In Vercel/Lambda, the function host can terminate the process when the request returns, killing the in-flight async work. Side effects (DB writes, alerts, audit) may never complete.

**Codebase instances (14 found)**:
- 4 in `apps/main/src/inngest/abuse-recompute-nightly.ts` (Greptile-flagged)
- 4 in `apps/main/src/lib/abuse/counters.ts` (NEW — same pattern)
- 2 in `apps/main/src/lib/ai/{call-wrapper,stream-wrapper}.ts` (NEW)
- 2 audit-log writes — `apps/main/src/lib/crypto/credential-cipher.ts:104`, `apps/main/src/lib/supervisor/metrics.ts:33`
- 2 chat-side fire-and-forget — `apps/main/src/app/api/chat/route.ts:179` (streaming response keeps process alive — likely OK)

**Why slips through**: under load with fast-completing async work, the void calls usually finish before termination — pattern works "most of the time."

**Prevention**:
- **Doctrine** (CLAUDE.md): "In serverless code, `void <asyncFn>()` is dangerous — the host can kill the process before the work completes. Either `await` it, OR add `// allow-void-async: <reason>` justifying that the work is idempotent retry-safe."
- **ESLint** (proposed): `atc/no-void-async-without-comment` — flags `void <ident>(...)` unless preceded by an `// allow-void-async` comment with a justification on the same comment block. Forces every void to be a deliberate decision.

### 9. Wrong assertPermission action for multi-operation routes

**Symptom**: one route handles multiple semantically-different operations (e.g. self-edit AND coordinator moderation) but calls `assertPermission` once with one `(resource, action)` pair. Either over-permissive (members can moderate) or under-permissive (owners blocked from moderation).

**Codebase instances (1 confirmed)**:
- `apps/main/src/app/api/forums/messages/[id]/route.ts` (Greptile-flagged) — `assertPermission("forums", "edit_message")` covers both self-edit and coordinator hide/unhide/pin

**Other suspects (each multi-method route is a candidate)**: routes that switch on `body.action` or have multiple HTTP methods need per-operation review.

**Why slips through**: type system doesn't know that "edit_message" semantically maps to one of two unrelated operations.

**Prevention**:
- **Doctrine** (CLAUDE.md): "If a route handles multiple semantically-distinct operations (multiple HTTP methods OR multiple `body.action` values), each operation MUST have its own `assertPermission` call with the correct `(resource, action)` pair. Don't reuse a single gate."
- **Code review**: explicit checklist item for routes with `action` field in body or multiple methods.

### 10. Idempotency-row written BEFORE dispatch

**Symptom**: webhook handler inserts dedup row, THEN dispatches event handler. If the process crashes after the insert but before the dispatch, the next retry from the external service is rejected as a duplicate — work never completes.

**Codebase instances (1 confirmed)**:
- `apps/main/src/lib/stripe/webhook-handler.ts` (Greptile-flagged)

**Why slips through**: crash-between-insert-and-dispatch is a low-probability race that doesn't appear in normal testing.

**Prevention**:
- **Doctrine** (CLAUDE.md): "Idempotency rows should be written AFTER the dispatched handler completes successfully. The row's existence indicates 'fully processed,' not 'received.' Use a separate `processing_started_at` for in-flight tracking if needed for reconciliation."
- **Probe**: error-injection probe (planned, see `docs/runbooks/error-injection-probe-design.md`) covers this — inject a crash after the insert, assert the retry succeeds.

### 11. Untrusted input flowing into state-machine actions

**Symptom**: a function like `progressTo(tenantId, stage)` is called with a `stage` argument derived from request body, without validating that the input is a valid transition.

**Codebase instances (1 confirmed)**:
- `apps/main/src/app/api/admin/tenants/[id]/review/route.ts:139` — `revertTo(tenantId, body.revert_to_stage)` accepts admin-supplied stage without checking it's behind the current stage

**Other state-machine callers**: every `progressTo(ctx.tenant_id, "literal")` uses a string literal — those are safe.

**Why slips through**: the literal-arg pattern is everywhere and looks identical at the call site.

**Prevention**:
- **Doctrine** (CLAUDE.md): "State-machine transition functions must validate inputs at the function boundary. If `progressTo` accepts any non-literal value, the function itself must enforce: (a) target stage exists in the enum, (b) transition is allowed from current stage. Don't delegate validation to callers."
- **ESLint** (proposed): `atc/state-machine-input-must-be-literal` — flags `(progressTo|revertTo|transitionTo)(<expr>, <non-literal-expr>)` so any dynamic call goes through an explicit waiver comment.
- **Code-level fix**: amend `progressTo`/`revertTo` to assert target stage is enum-valid AND is a permitted transition from current. Defense-in-depth even when callers pass literals.

### 12. Webhook signature encoding mismatch

**Symptom**: webhook signature decoded using the wrong encoding (hex vs base64 vs base64url) — every valid signature fails, every downstream enforcement (suppression list, callback handling) silently inoperative.

**Codebase instances (1 confirmed)**:
- `apps/main/src/app/api/webhooks/resend/route.ts:19` — `Buffer.from(sig, "hex")` but Svix uses base64url

**Other webhook handlers verified**: Stripe uses stripe-sdk's `constructEvent` which handles encoding internally; GitHub uses HMAC hex (correct).

**Why slips through**: type system doesn't know what encoding the signature uses; tests with mock signatures use the same wrong decode and pass.

**Prevention**:
- **Doctrine** (CLAUDE.md): "When integrating a new webhook source, capture the signature encoding (hex / base64 / base64url) at integration time. Add a brief comment at the verification site naming the provider and encoding (`// Svix uses base64url`)."
- **Test fixture**: every webhook handler should have a unit test using a real recorded signature from the provider (one fixture per provider). A signature-encoding mismatch fails the test deterministically.
- **Runbook**: maintain a per-provider signature-format table somewhere reachable (suggestion: `docs/runbooks/webhook-signature-formats.md`).

---

## Round-2 prevention plan summary

| Pattern | Codebase instances | Best prevention | Status |
|---|---|---|---|
| 7. Zero-row CAS | 3 | Doctrine + code review | Doctrine to add |
| 8. Void async in serverless | 14 (4 likely real bugs) | ESLint rule `no-void-async-without-comment` | Rule to ship |
| 9. Wrong action gate | 1 | Doctrine + code review | Doctrine to add |
| 10. Idempotency-before-dispatch | 1 | Doctrine + error-injection probe | Doctrine to add; probe deferred |
| 11. Untrusted state-machine input | 1 | Defense-in-depth in `progressTo`/`revertTo` + ESLint rule | Code fix + rule to ship |
| 12. Signature encoding mismatch | 1 | Per-provider runbook + recorded-signature unit tests | Runbook to add |

**Recommendation**: defer the two new ESLint rules + per-provider runbook to a separate session — the doctrine + the existing patterns + the punch list cover the immediate fixes. Schedule the rules when there's bandwidth.

---

---

## Later additions (post-round-2 incidents)

### 13. Destructive migration ships before the read-switchover (#137)

**Symptom**: a migration drops or renames a Postgres column while app code still references it. Column names live in app code as **strings** inside Supabase query chains (`.from("quotes").select("cruise_line")`), so `tsc` is completely blind — nothing fails to compile, nothing fails until those readers 500 in prod.

**Codebase instance**: #137 — the §38 expand + backfill + CONTRACT migrations all landed in one commit, dropping 9 columns off `quotes` while readers still SELECTed them. The customer quote view `/q/[token]` was a 10th reader missed even by the follow-up switchover.

**Why slips through**: the type system can't see column names in query strings; happy-path tests use the new schema.

**Prevention**:
- **Doctrine** (CLAUDE.md): expand-migrate-contract is THREE separate merges, in order — (1) **expand** (add new columns/table, dual-write if needed), (2) **switch reads** (`grep -rn '<column>' apps/*/src` for EVERY reader — it's a string, tsc won't help — repoint them, ship + deploy), (3) **contract** (drop old columns, only after step 2 is live). Never bundle the contract drop into the expand or read-switch PR.
- **CI gate**: `pnpm check:dropped-columns` (CI step "Dropped-column reader guard") fails any PR where app code names a dropped column inside a Supabase query string within its `.from("<table>")` chain. Table-aware (`quotes.cruise_line` dropped ≠ `bookings.cruise_line` live) and whole-word (`total_amount` ≠ `total_amount_cents`). **Limits**: only sees columns named as STRINGS near their `.from` — a `.select("*")` + later `row.col`, or a column never on the table, slips through. The gate is a backstop, not a substitute for step 2.

### 14. assertPermission pair missing from the grants matrix (#1173)

**Symptom**: a route under `apps/main/src/app/api/` calls `assertPermission(req, { resource: "X", action: "Y" })` with an `(X, Y)` pair absent from `permission-grants.ts` → silent 403s for every legitimate caller.

**Codebase instance**: #1173 — 58 silent 403s. `tsc` can't catch this class (resource and action are plain strings); E2E tests bypass `isPermitted` via `role='tenant_owner'`, so they pass too. Only the static sweep catches it.

**Why slips through**: strings again — neither the type checker nor the owner-role E2E path exercises the missing grant.

**Prevention**:
- **Same-PR rule** (CLAUDE.md): when you add a route that calls `assertPermission`, in the **same PR** (1) add the `key("resource", "action")` entry to the correct set in `apps/main/src/lib/auth/permission-grants.ts`, (2) add the matching tuple to `permission-grants.test.ts` under the right array (`READ_PAIRS` / `SELF_SERVICE_PAIRS` / `AGENT_ONLY_PAIRS` / `OWNER_ONLY_PAIRS`).
- **CI gate**: `pnpm check:permission-matrix` (CI step "Permission-matrix guard") must pass before push. Pre-existing gaps are tracked in `scripts/permission-matrix-baseline.txt`; remove a baseline entry once its grant is added.

---

## #1393 G1–G6 guards (items 15–20)

These six were added with the #1393 guard sweep. Each has a `pnpm check:*` gate that fails on NEW occurrences while freezing pre-existing debt in a baseline file. CLAUDE.md carries the one-line titles; the full rationale is here.

### 15. Admin route doesn't assert platform-admin in the handler (#1393/G5)

The `proxy.ts` admin gate is only a cookie *shape* check; real authority is the per-route assertion. Any new `app/api/admin/**/route.ts` must call an authority gate in-handler (main: `assertPlatformAdmin*` / `MAIN_APP_ADMIN_API_KEY` constant-time compare; rag: a `service_identifier` check against `"platform-admin"`). `pnpm check:admin-auth` ("Admin-route auth guard") enforces that an authority token is *present* (presence check, not flow analysis); intentional exemptions live in `scripts/admin-route-auth-baseline.txt`. Separately, mutating rag admin routes must also gate `scope === "write"` (convention, not enforced by this guard — see F-rag-auth-02).

### 16. Raw error `.message`/`.details` echoed into an API response (#1393/G1)

Postgres/Supabase error text embeds table/column/constraint names (schema disclosure). Route caught errors through `dbErrorResponse(error)` (`apps/main/src/lib/api/db-error-response.ts`): log server-side under a random ref, return a generic message + ref. `pnpm check:error-egress` ("Error-message-egress guard") blocks NEW `{ detail|message|error: <err>.message }` response shapes; ~70 pre-existing sites are frozen in `scripts/error-message-egress-baseline.txt` (burn-down tracked in #1395). The guard catches the direct form, not indirection (`const m = err.message; send({message:m})`) — the audit agents cover that.

### 17. Stored/rendered URL fields use `z.string().url()` instead of `safeUrl` (#1393/G2)

A bare `z.string().url()` accepts `file://`, cloud-metadata (`169.254.169.254`), and RFC1918 hosts; persisted then rendered into an `<img src>`/`<a href>` it's a client-side SSRF / unsafe-scheme vector. Use `safeUrl` from `@atc/contracts` (http/https + internal-host deny) for `source_url`/`image_url`/`*_url` ingest fields, and route server-side outbound fetches of such URLs through `lib/net/ssrf-guard.ts` (`fetchGuarded`). `pnpm check:url-validator` ("URL-validator guard") blocks new `z.string().url()` in app/contract code; `env.ts` operator-config URLs are exempt (trusted and may be non-http, e.g. `redis://`).

### 18. Counter/financial mutation done as read-modify-write (#1393/G3)

`.update({ count: prevCount + 1 })` / `.update({ balance: current - amount })` computes the new value in app code from a previously-read row, so two concurrent requests both read the old value and the second clobbers the first → quota overrun or money double-counted (Day-1 F-pay-01 / F-sm-01 / F-sm-02). Use a DB-side atomic increment (an RPC running `col = col + n` in SQL) or a CAS reserve-row (`.eq("count", expected)` + `safeAwaitRowCount`). The `counter-rmw` detector in `pnpm check:d091` ("D-091 anti-pattern gates") flags `.update({ <counter/balance/quota field>: <var> ± … })`; existing debt is baselined and the gate fails on NEW occurrences. A derived *absolute* value on such a field (not an RMW of the stored counter) is the false-positive class — suppress with `// d091-allow:counter-rmw <reason>`.

### 19. Public/anon rate limit backed by a module-level `Map`/`Set` (#1393/G4)

A limiter kept in process memory is per-instance under Fluid Compute: each warm instance enforces it independently and a cold start resets it, so spreading requests across instances bypasses the cap (Day-1 F-tok-01, F-rag-wh-01). Use Redis (`incr`/`expire` via `@/lib/redis/client`, failing **closed** in production) or a DB-atomic counter — the reference is `apps/rag/src/lib/rate-limit/feedback-limit.ts`. For signed webhooks, verify the signature **before** the rate-limit check and key the bucket on a value from the *verified* body, never on a spoofable `x-forwarded-for`. `pnpm check:rate-limit-store` ("In-memory rate-limit guard") flags a NEW module-level `new Map()`/`new Set()` whose variable name reads like a limiter (`rate`/`limit`/`throttle`/`attempt`/`bucket`/`quota`/`hits`); in-process *caches* (other names) are fine. Pre-existing limiters are baselined; accepted-risk per-instance limiters carry an inline `// inmem-ratelimit-allow:<reason>`.

### 20. Webhook has a signature but no replay protection (#1393/G6, extends #12)

A valid HMAC proves the body was signed, not that it's *fresh*; a captured-then-replayed signed delivery (or a leaked-then-rotated secret) re-applies the effect — re-poisoning a feedback signal (F-rag-wh-02), re-firing a transition, double-counting an event. Every inbound-signature handler must carry a replay defense: a timestamp-tolerance window (Stripe `constructEvent`, Svix signed timestamp), a dedup/idempotency row keyed on the provider's delivery id (`stripe_webhook_events`), a nonce, or a monotonic version guard (`source_revision >= incoming` makes a replay a no-op) — plus a per-provider **replay fixture test** that asserts the second delivery of a captured body is rejected/deduped. `pnpm check:webhook-replay` ("Webhook replay-protection guard") flags a NEW handler that reads an inbound signature but shows no replay signal; signature-primitive `*-signature.ts` helpers are exempt (replay is the caller's job). Pre-existing gaps are baselined; if protection lives in an imported handler or the risk is accepted, add an inline `// webhook-replay-allow:<reason>`.

### 21. Server action mutates rows scoped by a client-supplied owner id (#221/#318)

**Symptom**: closest neighbor is #11 (untrusted input into a state-machine action) — the same shape one level down: a server action authenticates the caller and schema-validates its input, then scopes a mutating `.eq('<ownership column>', …)` (or `.rpc(...)`/`delete()`/`update()`/`insert()`/`upsert()`) by an owner/account id read off the **request** rather than derived from the session. A well-formed uuid belonging to another tenant passes validation cleanly — validity isn't authority.

**Why slips through**: validation and authorization look identical in a diff; a reviewer sees `auth()` called and a zod-parsed body and moves on, without checking which party the ownership value's binding traces back to.

**Prevention**: Harvey's mechanical layer catches the narrow, AST-provable slice — `detectClientSuppliedOwnerId` (`src/detectors/app-router.ts`, taxonomy `M1 — Client-supplied owner id trusted by authenticated action`) fires only when all four hold: an ownership-column `.eq()` (never a bare `id`), on a mutating chain, whose value roots in a parameter rather than a session binding, with no explicit session-vs-client comparison guarding it — emitted `review`/`Likely`, never free-count, since the AST can't see authorization living in a wrapper it can't reach. Corpus: `P-AUTHN-CLIENT-OWNER(-DELETE)` + two negatives (`src/scan/calibration/m9-authz.entries.ts`; ground truth in `targets/calibration/GROUND-TRUTH.md`). The two related shapes #221 catalogued have since parted company, and this sentence used to state both as permanently semantic/paid-tier (#1684, re-measured 2026-08-01). Trusting a client-supplied security-relevant *value* is now MECHANICAL at review tier across all three members — `harvey-client-trusted-role`, `harvey-client-trusted-price` (#1373, the price/trial member) and the `client-payment-amount`/`client-priv-header` leftover-auth greps — scored by `P-CLIENT-TRUSTED-ROLE`/`P-CLIENT-TRUSTED-PRICE`/`P-CLIENT-PAYMENT-AMOUNT`/`P-CLIENT-PRIV-HEADER` against `N-SERVER-DERIVED-PRICE`, and confirmed on real code (semgrep 1.164.0 + `auth.yml` fires `harvey-client-trusted-price` on the pinned vercel/nextjs-subscription-payments clone at `utils/stripe/server.ts:69` and `:76`). A permission check present *only* in the UI is still uncaught, and is recorded as a MEASURED GAP tracked on #1679 rather than as a boundary: `P-CLIENT-RENDER-AUTHZ`/`P-MW-SOLE-AUTHZ` are `expectedTier: "none"` with `gapKind: "measured-gap"`, and since #1677 any rule that reaches either row fails the graduation guard by name. See also the two `briefs/scan-extras.txt` HIGH-section lenses.

---

## Round-3 patterns (post 2026-07-01 principal architecture review)

Vendored from ATC's canonical catalog (there numbered 21–26) @ commit `04a565d`. Harvey renumbers to **22–27** because Harvey's item 21 (client-supplied owner id) is Harvey-specific and has no ATC counterpart. Codebase instances/paths below are ATC's, retained as illustrative examples (as items 1–20 are). These six classes are concurrency / idempotency / integrity shapes — Harvey surfaces them in the M1 semantic pass (`briefs/scan-extras.txt`, MEDIUM section) and, where a live stack exists, the M2 dynamic pen-test; none is a mechanical-tier AST detector.

### 22. Claim-before-send in batch jobs

**Symptom**: A batch job that sends (email/webhook/external call) then stamps the row has sent twice on overlap or retry. A late sender can flip the sent flag while an early retry of the same job is mid-send.

**Codebase instances (2 found)**:
- `apps/main/src/lib/cron/task-reminders-fire.ts` (Greptile-flagged — #1581)
- `apps/main/src/inngest/precruise-generate-and-send.ts`, `apps/main/src/inngest/pre-cruise-email-scheduler.ts` (Greptile-flagged — #1582)

**Why slips through**: single-run tests pass. Catching requires concurrent job overlap or a strict retry within the send window — both invisible in normal testing.

**Prevention**:
- **Doctrine** (CLAUDE.md): "In batch senders, CAS-claim the row FIRST using `.update({sent_at: <val>}).is('sent_at', null).select('id')`. Skip the send if zero rows were claimed. Stamp-after-send will double-send on retry."
- **Code pattern**: For every `.send()` / `.dispatch()` in a loop, ensure a guarding `.update().is('sent_at', null)` precedes it, with the returned rowcount check.

### 23. Collectively-atomic multi-writes

**Symptom**: Two or more dependent writes where a mid-sequence failure + retry duplicates or drops one side. A process crashes after row A commits but before row B, so the retry succeeds for row B but row A was already written — a state invariant is broken (split credits/debits, half-created relationships, orphaned records).

**Codebase instances (4 found)**:
- `apps/main/src/lib/import/promote.ts`, `apps/main/src/inngest/import-pipeline.ts` (Greptile-flagged — #1576)
- `apps/main/src/inngest/commission-split-on-received.ts` (Greptile-flagged — #1578)
- `apps/main/src/lib/ai/batch/reconcile.ts`, `apps/main/src/lib/ai/batch/flush.ts` (Greptile-flagged — #1599)
- `apps/main/src/app/api/groups/route.ts` (Greptile-flagged — #1600)

**Why slips through**: happy-path tests write both rows successfully; the crash-in-between race is invisible without chaos injection.

**Prevention**:
- **Doctrine** (CLAUDE.md): "If a handler writes 2+ rows where one logically depends on the other, either (1) wrap both in a Postgres RPC (single atomic commit), or (2) ensure every row is individually idempotent (unique key + 23505-catch), AND the idempotency short-circuit doesn't skip LATER writes."
- **Code pattern**: Mark such functions with `// collectively-atomic-writes: <reason>` and verify in code review.
- **Test fixture**: error-injection probe (planned) will inject crash after row 1, assert retry succeeds without duplication.

### 24. Deterministic idempotency keys on external sends

**Symptom**: A retryable context sends to an external API (Resend, Stripe, Apify) without passing an `Idempotency-Key` header derived from stable identifiers — two retries send twice, or the API de-duplicates across different logical requests.

**Codebase instance (1 found)**:
- `apps/main/src/lib/email/send.ts` (Greptile-flagged — #1580)

**Why slips through**: the Resend/Stripe API de-dup window is often minutes or hours; single-run tests don't retry and happy-path never hits the window.

**Prevention**:
- **Doctrine** (CLAUDE.md): "Every `.send()` / Stripe/Apify call from a retryable context (Inngest, webhook handler, cron) must pass an `Idempotency-Key` header derived from immutable identifiers (message_id, booking_id, event_id) + operation type. Format: `sha256(tenant_id|message_id|version)` or similar."
- **Code pattern**: `fetch(url, { headers: { 'Idempotency-Key': idempotencyKey(...) } })`.

### 25. DB uniqueness wherever app code assumes it

**Symptom**: Code deduplicates with SELECT-then-INSERT (query for existing, insert if missing) but the schema has no UNIQUE index. A race: between the SELECT and INSERT, another request writes the same row — first request's INSERT succeeds with a duplicate, then `.maybeSingle()` on a later read fails.

**Codebase instances (1 found, 3 dedup sites)**:
- `apps/main/src/lib/import/promote.ts` (Greptile-flagged — #1575; commissions/bookings/contacts dedup all route through this file)

**Why slips through**: the race is low-probability; tests run serially.

**Prevention**:
- **Doctrine** (CLAUDE.md): "If code dedupes on (a, b), schema MUST have `UNIQUE(a, b)` + a 23505 handler. `.maybeSingle()` is not a substitute."
- **Runbook**: add a migration checklist item: "Every `INSERT ... ON CONFLICT` block or SELECT-then-INSERT pattern must reference a UNIQUE constraint in the schema."

### 26. Bounded queries on user-growing tables

**Symptom**: A `.select()` on a table that grows unbounded (messages, bookings, email_log, ai_call_log, notifications, forum_posts) has no `.limit()` or pagination. PostgREST silently truncates to `max-rows` (hard default 1000 on Supabase), and with `.order('id')` ascending the truncation **drops the newest rows** — data loss by default.

**Codebase instances (2 found)**:
- `apps/main/src/lib/chat/conversation-history.ts` (Greptile-flagged — #1587)
- `apps/main/src/app/api/quotes/route.ts`, `apps/main/src/app/api/groups/route.ts`, `apps/main/src/app/api/admin/resource-utilization/route.ts`, `apps/main/src/app/api/admin/legal-docs/route.ts` (Greptile-flagged — #1588)

**Why slips through**: the limit is silent (no error, just fewer rows). Tests with small datasets fit under the cap.

**Prevention**:
- **Doctrine** (CLAUDE.md): "Every `.select()` on a user-growing table carries `.limit(<N>)` and/or `.range(from, to)`. No unbounded cursor queries."
- **ESLint** (proposed): `atc/no-unbounded-user-table-query` — flag `.from(<table>).select(...)` on known user-growing tables without a `.limit()` or `.range()`.

### 27. Webhook state-application needs ordering protection, not just replay dedup

**Symptom**: At-least-once delivery + unordered delivery means a stale re-delivery or an out-of-order newer message can overwrite fresh state. Replay dedup alone (signature + nonce) prevents the same request firing twice, but not a replayed *old* request overwriting a *new* one from the same provider.

**Codebase instance (1 found, fixed)**:
- `apps/main/src/lib/stripe/webhook-handler.ts` (Greptile-flagged — #1583; fixed in PR #1642 via `subscription_status_event_at` ordering guard)

**Why slips through**: the ordering hazard is orthogonal to signature validation; signature tests pass because they test the same event replayed, not different events arriving out of order.

**Prevention**:
- **Doctrine** (CLAUDE.md): "A webhook handler that updates state based on the event payload must compare `event.created_at` against the last-applied event's timestamp (or `source_version` against `last_applied_version`), or re-fetch the live state from the provider before applying. Replay protection (signature + dedup) prevents *the same event* re-firing; ordering protection prevents *a stale event* overwriting fresh state."
- **Code pattern**: before `.update({state_field: event.new_state})`, check `event.created_at > row.last_event_at` (or similar), or re-fetch the canonical state from the provider and apply conditionally.

---

## Harvey-audit patterns (external audit, 2026-07; Harvey-hardening PR)

Vendored from ATC's canonical catalog (there numbered 27–28) @ commit `04a565d`. Harvey renumbers to **28–29** (the same +1 offset as the Round-3 block). These two classes originated in Harvey's own external audit of ATC; ATC's CI-gate names below are ATC-specific, retained as illustrative examples. In Harvey's product both are M1 semantic-pass lenses (`briefs/scan-extras.txt`), and item 29's mechanical half is also covered by the env-schema-completeness (#679) and rotation-pair (#680) detectors.

### 28. SECURITY DEFINER functions must scope to the caller — no parameter-only oracles

**Symptom**: A `SECURITY DEFINER` function takes an identifier parameter and returns status/existence (or performs a privileged write) without consulting `auth.uid()`/`auth.jwt()`/caller context anywhere in its body. DEFINER runs as the owner and bypasses RLS, so every role the function is granted to can probe arbitrary IDs — a tenant-status/existence enumeration oracle, or (the write case) an escalation primitive.

**Codebase instances**:
- `tenant_is_active(target_tenant_id)` — parameter-only tenant-status oracle (Harvey M1 finding, refs #2006 — reviewed and accepted as documented; frozen in the baseline)
- 18 further DEFINER write sites + 5 read sites frozen in `scripts/rls-semantics-baseline.txt` pending review

**Why slips through**: the function works perfectly for its intended caller; the oracle is only visible by asking "who ELSE can call this, with whose IDs?" — which no happy-path test asks. RLS being enabled on the underlying table gives false comfort (DEFINER bypasses it).

**Prevention**:
- **CI gate**: `pnpm check:rls-policy-semantics` (the `definer-authz` and `definer-oracle` sub-checks) — NEW un-caller-scoped DEFINER functions fail; existing ones are frozen in `scripts/rls-semantics-baseline.txt`.
- **Doctrine** (CLAUDE.md #27): a DEFINER function must verify the caller (own-row, role, or tenant membership via `auth.uid()`/`auth.jwt()`) before returning data or writing, or have EXECUTE revoked from client roles.

### 29. Every secret registers in the env schema at integration time, with a rotation path

**Symptom**: A secret is consumed via a raw `process.env.X` read that never appears in the app's canonical env schema (`apps/<app>/src/lib/env.ts`), and/or its verify site is a single static comparison with no `_CURRENT`/`_PREVIOUS` acceptance — so the secret is invisible to boot validation and the secret inventory, and cannot be rotated without an outage.

**Codebase instances**:
- `MAIN_APP_ADMIN_API_KEY` — static non-rotating seam bearer, absent from the main app's env schema (Harvey M1 finding, refs #2002; strategy-B fix pending)
- 53 undeclared `process.env` reads (35 distinct vars) frozen in `scripts/env-schema-baseline.txt` (refs #2004)

**Why slips through**: the read works in every environment where the var happens to be set; the gaps (typo'd var silently undefined, un-inventoried secret, rotation requiring simultaneous redeploys) only bite operationally.

**Prevention**:
- **CI gate** (mechanical half): `pnpm check:env-schema` — a NEW `process.env` read of an identifier not declared in that app's env schema fails; existing debt is frozen in `scripts/env-schema-baseline.txt`.
- **Reviewer-enforced half (honest limitation)**: the rotation-pair requirement — verify sites accepting `_CURRENT` **and** `_PREVIOUS` values (the `SERVICE_JWT_*`/`FORENSICS_ENCRYPTION_KEY_*` pattern) instead of one static bearer comparison — is NOT mechanically checked; no static scan can tell a rotating verify site from a static one reliably. The audit agents and this catalog entry carry that half.

---

## Harvey detector-coverage audit (#1197, 2026-07-27)

This catalog is described elsewhere (CLAUDE.md) as "also the M1 taxonomy source," which reads as
though every item has a Harvey detector behind it. #1197 found that item 19 did NOT (a regex bug,
since fixed) and asked for a systematic pass: which of the 29 items does Harvey actually ship a
detector for, versus only ATC's own CI gate (`pnpm check:*`, an ESLint rule, or a doctrine line)?
Measured by grepping Harvey's semgrep rule ids, TS detector `taxonomy:` strings, and the pentest
(M2 dynamic) probes for each item's theme — not by assuming the prevention column above implies a
Harvey detector, since most of those are ATC-repo-local mechanisms Harvey never shipped.

**Covered (Harvey ships a detector or probe)**: 1 (M5 unused-parameter, slop.ts), 2
(`harvey-fail-open`), 3 (`harvey-unchecked-mutation`), 4 (`harvey-secret-in-url-param`), 5 (service-
role/RLS family — service-role-literal.ts, job-tenant-scope.ts, checkMigrationRlsBypass and
siblings), 7 (`harvey-zero-row-update`), 8 (`harvey-void-async`), 16 (`harvey-db-error-disclosure`),
17 (`harvey-ssrf-fetch` static + `ACTIVE-SSRF` M2 dynamic — the SSRF risk class, not the specific
`z.string().url()`-vs-`safeUrl` schema distinction), 18 (counter-race.ts), 19
(`AUTH-inmemory-rate-limit`, #1046 — fixed by #1197 to match a generic-typed `new Map<K, V>()`), 21
(`detectClientSuppliedOwnerId`, app-router.ts), 26 (M7 "Unbounded select" — framed as a performance
finding, but the same shape), 28 (definer-review.ts / definer-classifier.ts / SECURITY DEFINER
checks in supabase-static.ts), 29 (env-schema.ts #679 mechanical half; rotation-pair half is an
honest reviewer-enforced limitation, same as ATC's own).

**Partially covered**: 11 (untrusted state-machine input) — only a live M2 dynamic workflow-bypass
probe (`business-logic.ts`'s `BIZLOGIC-WORKFLOW`), no static/mechanical detector for the AST shape
(`progressTo`/`revertTo` called with a non-literal). 15 (admin route missing platform-admin) —
`AUTH-sensitive-route` (leftover-auth.ts) catches an admin/debug/seed route with NO auth-call hint
at all, but not specifically "authenticated but at the wrong authority level," which needs to know
the app's own authority model.

**Was "not covered" — nine items, re-measured and mostly closed (#1230, 2026-07-27)**: items 6, 10,
12, 13, 22, 23, 24, 25 and 27 were recorded here as having no Harvey detector, with the blanket
explanation that "every one of these is a cross-statement or cross-time dataflow question a
mechanical AST/semgrep pass is a poor fit for". **That blanket claim was wrong for six of the
nine.** It was written at the moment the work stopped, was never re-tested, and reads in MEASURED's
register while being ASSUMED — the shape CLAUDE.md's recorded-reason doctrine exists to catch. What
the re-check found: the cross-TIME part is the failure mode (a crash, a retry, an overlapping run,
a later deploy), but the DEFECT in six of them is an ordering or naming fact between statements
already in the tree, which is exactly what an AST reads.

**Now covered (shipped by #1230)**: 6 (`stale-quota-read.ts` — an allowance bound from a
`.from(…).select(…)` read, compared inside a loop that awaits work and never re-reads; the DB-read
requirement is what clears the running-total-against-a-ceiling FP class), 10 and 22 and 24
(`idempotency.ts` — a dedup row inserted before the handler it guards; a batch send stamped after
dispatch instead of CAS-claimed before; an external send from a retryable path with no idempotency
key), 12 (`webhook-signature.ts` — the "per-provider expected-encoding table Harvey doesn't have"
turned out to be five documented rows keyed on the signature HEADER NAME, which carries the
provider), 13 (`migration-column-drift.ts` — "needs migration history over time" was false: the
migration files ARE the history and are checked in, so it folds to a single-snapshot pass with no
VCS archaeology). Corpus: `src/scan/calibration/b23-d091-gaps.entries.ts`, one planted positive and
one benign lookalike per class.

**Now covered (shipped by #1257)**: 25 (`dedup-unique.ts` — a single-row `.select().eq(…).maybeSingle()`
read followed in the same function by an insert writing those same columns, when no UNIQUE or
PRIMARY KEY set the migrations declare is a subset of the columns read). Three benign lookalikes,
two of them on a deliberately UNCONSTRAINED table, so the schema does not clear them and each is
cleared only by an app-side conjunct.

**Still not covered, and why — the TWO that survived the re-check.** Each is planted in the same
corpus at `expectedTier: "none"` so the gate holds it: a rule firing on one is a GATE FAIL, and the
gap cannot quietly graduate into a claimed catch.
It was three until #1257 shipped item 25, and the label is why: item 25 was recorded as a
`measured-gap` rather than a boundary, so it stayed outstanding work with a falsifier watching it
instead of becoming a permanent decline.

- Item 23 (collectively-atomic multi-writes) — M1 semantic pass.

  > REASON: No mechanical rule for collectively-atomic multi-writes; two dependent writes are indistinguishable from two unrelated writes without knowing what the rows mean.
  > KIND: decisional
  > PROVENANCE: MEASURED 2026-07-27
  > OWNER: Harvey product
  > DECISION: #1230
  > TOUCHES: src/scan/idempotency.ts targets/calibration/src/d091/atomic-multi-write.ts

  A rule keyed on "two writes in one function with no RPC/transaction wrapper" fires on every
  multi-entity create handler in every codebase. Whether the rows form ONE invariant is a judgement
  about domain meaning, not an AST fact — the same unshippability that keeps item 20 at LLM tier.

- Item 27 (webhook state-application ordering) — **NO LONGER DECLINED. Shipped #1352, mechanical,
  review tier** (`webhookOrdering` in `src/scan/idempotency.ts`, scored by `P-D091-WEBHOOK-ORDERING`).

  The decline above read: *"the rule would have to prove the ABSENCE of a version/timestamp
  comparison anywhere reachable from the handler, including through an imported wrapper"*, with
  item 20 cited as the precedent. #1350/#1352 falsified the argument, not the precedent: four
  detectors in this same sweep prove an absence with the identical reach problem and answer it by
  scoping to the function body and stating that bound in the emitted finding — `express-powered-by`,
  `raw-body-limit`, `gha-permissions` and item 10's own `dedupBeforeDispatch`. Reach was never what
  decided it.

  What the rule actually costs is recorded instead of guessed. MEASURED 2026-07-31 over all 17
  pinned corpus repos (13,113 source files): 61,346 candidate functions, 176 with an event-derived
  `.update`/`.upsert`, 6 of those in a webhook path, and **zero** whose parameter carries an
  ordering field — no false positives and no true positives, so its FIELD precision is undefined
  rather than clean, and the finding's own evidence says so. The measurement also earned a
  narrowing before the rule shipped: 2 of the 6 were `crypto.createHmac(…).update(body)`, so the
  write must resolve to a Supabase `.from(…)` table or a prisma-style model call.

  Item 20 (`WEBHOOK-REPLAY`, #353/#425) remains an LLM-tier gap on its own merits; 27 shipping
  ahead of it is not an inconsistency, because the two ask different questions.

**Not covered — ATC-specific, not portable**: 9 (wrong `assertPermission` action for multi-
operation routes) and 14 (`assertPermission` pair missing from `permission-grants.ts`) both name
ATC's own auth-helper API and grants-file convention; a generic multi-tenant target has no
equivalent for Harvey to check against.

**Already a documented by-design gap, not new**: 20 (webhook replay protection) — `WEBHOOK-REPLAY`
already exists in the calibration corpus (`b17-race-unscoped.entries.ts`, #353/#425) as a measured
LLM-tier class with no mechanical rule by design, and flips the gate loud if one ever fires.

Item 19's regex bug and the eight OWASP multi-tenant gaps are closed; #1242 closed the ninth
(audit log entries without tenant context, `src/scan/audit-log-tenant.ts`). Of the nine listed
above, six shipped in #1230 and item 25 shipped in #1257 (`src/scan/dedup-unique.ts` — the app-side
dedup predicate folded against the UNIQUE/PRIMARY KEY sets the migrations declare, with a table the
pass never saw declared skipped rather than reported). The blanket "cross-statement or cross-time
dataflow" reason #1230 attached to all nine was false for seven of them.

---

## How this catalog gets used

- **At authoring time**: the CLAUDE.md doctrine lines (added to the "Things to be wary of" section) shape what gets written. Re-read every session.
- **At lint time**: ESLint rules in `packages/config/eslint-rules/` catch the mechanical patterns. Some default `error`, some opt-in `warn`.
- **At diff time**: `pnpm slop-check` (D-091) extends to cover these patterns where reasonable. Runs locally via `pnpm verify`; advisory only.
- **At CI time**: `cross-tenant-probe` and the new `error-injection-probe` catch the runtime-only failure modes.

## Adding a new pattern

1. Confirm it's a pattern (≥ 2 instances in real findings).
2. Add to this catalog with: symptom, examples, why-slips-through, prevention.
3. Implement the cheapest prevention layer first (doctrine line → ESLint → slop-check → probe). Add layers only if simpler ones don't catch.
4. Backfill: grep the codebase for existing instances and either fix them or document waivers.
