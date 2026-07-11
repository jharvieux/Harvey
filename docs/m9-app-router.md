# M9 — Next.js App Router boundary & rendering

Detector: `src/detectors/app-router.ts` (`detectAppRouterFindings`). Brief: `docs/scan-extras.txt`
(M9 section). Tests/fixtures: `src/detectors/app-router.test.ts`, `src/detectors/__fixtures__/`.

## Method

Static AST analysis over TypeScript/TSX source using the TypeScript compiler API
(`typescript`, already a devDependency — `ts-morph` is not present in this repo, so no new
dependency was added). `detectAppRouterFindings(files: { path, text }[])` parses every file with
`ts.createSourceFile` and runs each check below over the resulting ASTs, emitting `Finding[]`
(`src/findings.ts`). The server→client leak check needs sibling files (to know which imported
components are Client Components), so callers should pass the project's full relevant `.ts`/`.tsx`
source set, not one file at a time.

Findings route into §3 (security) for the four HIGH checks and §3b (performance) for the three MED
checks, tagged with a `taxonomy` beginning `M9 —`. All findings default to `status: "Open"` and a
generated `id` of the form `M9-01`, `M9-02`, ... (sequential per detector run — re-numbered, not
stable, across runs with a different file set).

## Checks

### Server → Client data leak — HIGH (`M9 — Server→client data leak`)

**Detects:** a non-`'use client'` file that (a) imports a component from a sibling file whose
leading directive is `'use client'`, (b) holds a variable bound to a raw Supabase query result
(`const { data: x } = await ...from(...).select(...)`, or the identifier form), and (c) passes that
variable whole into the client component — either `<Comp data={row} />` or `<Comp {...row} />`.

**Detection method:** AST. Client-component identity comes from the imported file's leading
directive; import resolution is relative-path only (`./Foo`, `../lib/Foo`, with `.ts`/`.tsx`/
`index.ts(x)` resolution) — path aliases (`@/components/Foo`) are not resolved, so a leak through
an aliased import is a **false negative**. A prop is only flagged when the *whole* query-result
variable is passed; `<Comp data={row.name} />` (a narrowed projection) is correctly treated as safe.
**Known false negative:** a leak that goes through an intermediate variable (`const dto = row; <Comp
data={dto} />`) or through an object literal that spreads a nested field (`<Comp data={{...row.x}}
/>`) is not tracked — the check only follows the direct query-result binding.

### Missing `server-only` guard — HIGH (`M9 — Missing server-only guard`)

**Detects:** a file that reads a secret-shaped `process.env.*` variable (name matches
`SERVICE_ROLE`, `SECRET`, `PRIVATE_KEY`, `API_KEY`, or `TOKEN`, excluding `NEXT_PUBLIC_*`) but has
no `import "server-only";`. This is the enforcement side of the leak check: a shared module like
this can be transitively pulled into a Client Component bundle with no build error.

**Detection method:** AST for the env-access and import-declaration checks; exempts `route.ts(x)`
and `middleware.ts` files (these are already server-exclusive by Next.js's own routing convention,
so requiring the guard there would just be noise) and files under a `'use client'`/`'use server'`
directive (a `'use server'` module is already guaranteed server-only by the Next compiler).
**Known false positive:** the secret-name pattern is a heuristic — an env var that happens to match
(`FEATURE_FLAG_API_KEY_ENABLED`) but isn't actually sensitive will still be flagged; a human should
confirm before reporting. **Known false negative:** secrets referenced only through a re-exported
constant (`import { SERVICE_ROLE_KEY } from "./config"`) rather than `process.env` directly aren't
traced back to their source.

### Server Action missing auth — HIGH (`M9 — Server Action missing auth`)

**Detects:** a Server Action (file-level `'use server'`, or a function whose body opens with an
inline `'use server'` directive) that calls a DB mutation (`.insert(`, `.update(`, `.upsert(`,
`.delete(`, or `.rpc(`) with no auth/session pattern (`auth.uid`/`getUser`/`getSession`,
`getServerSession`, `getCurrentUser`, `requireAuth`/`requireUser`/`requireSession`,
`assertPermission`/`assertAuthorized`, `checkAuth`, `verifySession`, or a bare `auth()` call)
anywhere in the action's body.

**Detection method:** AST to locate Server Actions and confirm the mutation call; the auth check
itself is a text-level pattern match over the action's source range (a real authority check that
uses a different name than the ones above is a **false negative** — the list isn't exhaustive.
Conversely a comment or unrelated string that happens to contain one of these words would be a
**false positive**, though that's unlikely in practice). Only scoped to actions that call a
mutation — a read-only action with no auth check is intentionally not flagged by this check (that's
a different, lower-severity gap not covered here).

### Server Action missing input validation — HIGH (`M9 — Server Action missing input validation`)

**Detects:** the same mutating Server Actions as above, flagged when the body has no schema-parse
call (`.safeParse(`, `.parse(` — excluding `JSON.parse(` — or a bare mention of `zod`, `valibot`,
`yup.`, or `ajv`).

**Detection method:** same text-level pattern match, same scope (mutating actions only). **Known
false positive:** validation performed by a helper function whose name doesn't match the pattern
(`const input = sanitize(formData)`) isn't recognized. **Known false negative:** a schema `.parse`
call that validates the *wrong* shape (e.g. parses `name` but not the `tenant_id` actually used in
the mutation) still satisfies the pattern — this check proves *a* parse call exists, not that it
covers every field trusted from the client.

### Unsafe / missing cache config — MED, best-effort (`M9 — Unsafe/missing cache config`)

**Detects:** a `page.tsx`/`layout.tsx` file that runs a Supabase `.from(...).select(...)`
query with no cache signal (`unstable_cache`, `"use cache"`, or a `revalidate` reference) anywhere
in the file. The check is suppressed if the file reads any dynamic API that forces rendering per-request
(`cookies()`, `headers()`, `noStore()`, `unstable_noStore()`, or direct `searchParams` access) — such a
route is dynamic by construction, so a missing cache config is expected and not flagged.

**Detection method:** file-level text heuristic, deliberately light per the brief. It cannot tell
cost-side "never cached" from isolation-side "cached without a per-key tag" — both failure modes
from the brief collapse into one finding, and a human has to read the code to tell which (if
either) applies. **Known false positive:** caching applied one layer up (a cached data-access
function imported into this file) won't be visible from this file's text and will still be flagged.

### Data-fetching waterfalls — MED, best-effort (`M9 — Data-fetching waterfall`)

**Detects:** two `const { data: x } = await ...from(...).select(...)` (or plain-identifier) query
declarations back-to-back in the same block, where the second's statement text doesn't reference
any name bound by the first (i.e. it isn't obviously reading the first query's result).

**Detection method:** AST for locating the two declarations; the dependency check is a substring
match against the first declaration's bound name(s), not a data-flow analysis — a dependency
expressed indirectly (e.g. through a helper function call) would be a **false positive** (flagged
as independent when it isn't). Only checks directly-adjacent declarations in one block; queries
separated by other statements, or split across nested blocks/branches, aren't compared (**false
negative**). Emits at most one finding per function to avoid pile-on noise on functions with more
than two queries.

### Accidental dynamic rendering — MED, best-effort (`M9 — Accidental dynamic rendering`)

**Detects two patterns, both scoped to `page.tsx`/`layout.tsx` files only:**
1. A direct call to `headers()`, `cookies()`, `noStore()`, or `unstable_noStore()` anywhere in the
   file.
2. The page's default-exported component destructuring a `searchParams` prop and then reading a
   field off it directly (property/element access, `await`ing it, or destructuring it) rather than
   only forwarding the whole object to a child component.

**Detection method:** AST. Pattern 2 deliberately treats "receives `searchParams` as a prop" as
fine and only flags an actual *read* — passing the object through untouched to a `<Suspense>`-
wrapped leaf (the brief's recommended fix) is correctly treated as safe. **Known limitation:**
because each file is analyzed independently, this can't see whether a *child* component (in another
file) reads `searchParams`/calls `headers()` high in the tree outside a Suspense boundary — the
brief's "read high in the tree" is approximated as "read in this route's own module," not a real
call-graph position. A leaf component that itself calls `cookies()` outside Suspense, one import
away, is a **false negative** here.

## Calibration target dependency (issue #9)

Issue #9 (shared calibration target) hadn't landed in `main` at the time this module was built, so
the checks above are tested against synthetic fixtures in `src/detectors/__fixtures__/` (one
positive + one negative example per check, plus extra negative cases for the router-level
exemptions) rather than a seeded example in a shared target. Wiring a seeded example of each HIGH
check into the calibration target is follow-up work once #9 lands.
