// PII / PHI / PCI data-classification detector (audit module M10) — "detect, don't ask."
//
// Matches DB column NAMES + types (never values) against a dictionary aligned to standard
// taxonomies — Google Cloud DLP infoTypes, Microsoft Presidio entity types, GDPR Art. 9 special
// categories, HIPAA's 18 PHI identifiers, PCI-DSS cardholder/sensitive-auth data — so it's
// privacy-safe and only needs a read-only connection (or a static schema description with the
// same {table_name, column_name, data_type} shape as information_schema.columns).
//
//   pnpm pii-classify --selftest
//   SUPABASE_DB_URL=... pnpm pii-classify                    # inventory a live DB (read-only)
//   pnpm pii-classify --schema supabase/migrations           # static schema, no DB needed (#250)
//   pnpm pii-classify --schema before/schema.sql init.sql    # multiple targets (#770), concatenated
//   pnpm pii-classify --schema prisma/schema.prisma          # Prisma DSL, not SQL (#758)
//
// PAID opt-in semantic layer (#855): add `--semantic` AND set ANTHROPIC_API_KEY to run an LLM
// pass over the columns the name dictionary could not resolve (names/types/table context only —
// never values). Absent either the flag or the key, behavior is exactly the name-based-only path
// above with zero network calls. Model: `--semantic-model <id>` / PII_SEMANTIC_MODEL env,
// default claude-sonnet-5.
//
// The --schema path parses `CREATE TABLE` columns straight out of migration SQL (one or more
// targets, each a directory of *.sql files or a single .sql file) via src/migration-sql-parse.ts's
// parseColumns — the same under-extract-rather-than-mis-extract parser the M1 detect-deeper
// classifiers use — so this runs the identical classifier over source-only engagements instead of
// needing a live DB. A target ending in `.prisma` isn't SQL at all — a Prisma app declares its
// schema in `schema.prisma`, not migration files, so that target is handled separately (#758): the
// target's own local Prisma CLI generates the equivalent SQL (`prisma migrate diff --from-empty`),
// which then feeds the SAME parseColumns parser; when the CLI isn't runnable (no local install),
// a lightweight schema.prisma model/field parser (src/prisma-schema-parse.ts) produces the columns
// directly instead.
// Requires `tsx` (the `pnpm pii-classify` script) rather than plain `node`, since it imports a
// TypeScript source file directly.
//
// FP discipline: a name-only dictionary over-matches on its own (see exclusionReason below) —
// every hit goes through an exclusion pass before it's returned, and ambiguous names get "low"
// confidence rather than an assertion, so they're flagged for review, not treated as fact.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { parseClassifiableColumns } from "../src/migration-sql-parse.js";
import { piiProtectionFindings, piiProtectionScope } from "../src/pii-protection-review.js";
import { parsePrismaSchema } from "../src/prisma-schema-parse.js";

const RULES = [
  // --- HIPAA PHI identifiers / GDPR contact & identity PII ---
  [/(^|_)e?mail(_|$)/, "EMAIL", "PII", "high"],
  [/(^|_)(ssn|social_security)(_|$)/, "US_SSN", "SENSITIVE_PII", "high"],
  [/(date_of_birth|(^|_)dob(_|$)|birth_?date)/, "DOB", "PII", "high"],
  [/(^|_)(phone|mobile|telephone|cell)(_|$)/, "PHONE", "PII", "high"],
  [/(^|_)fax(_|$)/, "FAX", "PII", "high"],
  [/(^|_)passport(_|$)/, "PASSPORT", "SENSITIVE_PII", "high"],
  [/(driver_?licen[cs]e|license_number)/, "DRIVERS_LICENSE", "SENSITIVE_PII", "high"],
  // #856: mother's maiden name and security question/answer are identity-verification / account-
  // recovery secrets (knowledge-based auth) — SENSITIVE_PII. Placed before the generic NAME rules so
  // `maiden_name` asserts MAIDEN_NAME (high) rather than falling through to the ambiguous NAME? flag.
  [/(maiden_name|mother_?maiden|mothers_maiden)/, "MAIDEN_NAME", "SENSITIVE_PII", "high"],
  [/(security_question|security_answer|secret_question|secret_answer)/, "SECURITY_QA", "SENSITIVE_PII", "high"],
  // #379: generic national/government-ID catch-all — the identifier shape non-US schemas use
  // (DLP/Presidio ship per-country recognizers; this is the fallback infotype for the rest).
  // Medium, not high: "ID card number" schemes vary widely, so it's a catch-all, not a validated
  // per-country pattern. Deliberately NOT matching bare `id`/`_id` — the compound names are the
  // guard against flooding every PK/FK column.
  [/(national_id|government_id|citizen_id|resident_id|id_card_number)/, "NATIONAL_ID", "SENSITIVE_PII", "medium"],
  [/(medical_record_number|(^|_)mrn(_|$))/, "MEDICAL_RECORD_NUMBER", "PHI", "high"],
  [/(health_plan|insurance_(id|number|policy))/, "HEALTH_PLAN_ID", "PHI", "high"],
  // #378: mac_address/mac_addr and license_plate/plate_number are HIPAA Safe Harbor identifiers
  // #13 (device identifiers) and #12 (vehicle identifiers) the original alternatives missed.
  [/(^|_)(device_id|imei|udid|mac_address|mac_addr)(_|$)/, "DEVICE_ID", "SENSITIVE_PII", "medium"],
  [/(^|_)(vin|vehicle_identification|license_plate|plate_number)(_|$)/, "VEHICLE_ID", "PII", "medium"],
  [/(biometric|fingerprint|retina|iris_scan|face_?id|faceprint|voiceprint)/, "BIOMETRIC", "SENSITIVE_PII", "high"],
  // #378: HIPAA Safe Harbor identifier #17 — full-face photographs and comparable images.
  // Medium, not high: many avatar_url columns are low-sensitivity app furniture, but under
  // HIPAA/GDPR they are worth a review-tier flag rather than silence.
  [/(photo_url|headshot|mugshot|profile_pic(ture)?|avatar_url|face_image|signature_image)/, "PHOTO", "PII", "medium"],
  // --- PCI-DSS cardholder / sensitive authentication data ---
  // CVV/CVC is "sensitive authentication data" — PCI-DSS forbids storing it post-authorization
  // at all, so a hit here is a compliance violation by itself (see INFOTYPE_POINT_OVERRIDES).
  [/(^|_)(cvv|cvc|card_verification|card_security_code)(_|$)/, "CVV", "PCI", "high"],
  // #376: PIN/PIN-block and full track/magstripe data are the other two members of PCI-DSS's
  // "sensitive authentication data, never store post-authorization" category CVV belongs to —
  // a hit is a compliance violation by itself (INFOTYPE_POINT_OVERRIDES scores each Critical
  // alone). Deliberately NO bare `pin` alternative: it collides with `pinned`/`is_pinned`
  // feature-flag naming and India's postal "PIN code", so only compound card/ATM names match.
  [/(^|_)(pin_block|pin_verification|atm_pin|card_pin)(_|$)/, "PIN", "PCI", "high"],
  [/(track_?1|track_?2|track_data|mag_?stripe)/, "TRACK_DATA", "PCI", "high"],
  [/(card_expir|card_exp_(month|year))/, "CARD_EXPIRY", "PCI", "medium"],
  [/(credit_?card|card_number|cc_num|(^|_)pan(_|$)|card_last4|card_brand)/, "CARD", "PCI", "high"],
  [/(^|_)(iban|account_number|routing|swift)(_|$)/, "BANK_ACCT", "PCI", "medium"],
  [/(stripe_customer|payment_method|payment_intent)/, "PAYMENT_REF", "PCI", "medium"],
  [/(wallet_address|crypto_address|btc_address|eth_address)/, "CRYPTO_WALLET", "SENSITIVE_PII", "medium"],
  // --- General PII (Presidio-style) ---
  [/(^|_)(ip|ip_address)(_|$)/, "IP", "PII", "medium"],
  [/(first_name|last_name|full_name|surname|given_name|middle_name)/, "NAME", "PII", "medium"],
  [/(^|_)username(_|$)/, "USERNAME_HANDLE", "PII", "low"],
  // #856: salary/compensation is sensitive personal-financial data; age is a HIPAA quasi-identifier
  // (an exact age >89 is a Safe Harbor identifier). Age is token-bounded so it never fires on `page`,
  // `usage`, `language`, `average`, `image`, `message`, etc.
  [/(^|_)(salary|compensation|annual_income)(_|$)/, "COMPENSATION", "SENSITIVE_PII", "medium"],
  [/(^|_)age(_|$)/, "AGE", "PII", "low"],
  [/(^|_)(address|street|city|zip|postal|postcode)(_|$)/, "ADDRESS", "PII", "medium"],
  [/(latitude|longitude|(^|_)geo|(^|_)lat(_|$)|(^|_)lng(_|$))/, "GEO", "PII", "low"],
  // --- GDPR Art. 9 special categories ---
  [/(political_(affiliation|party)|union_member(ship)?)/, "POLITICAL_OR_UNION", "SENSITIVE_PII", "high"],
  [/(genetic|dna_|genome)/, "GENETIC", "SENSITIVE_PII", "high"],
  // #856: word-bound each concept as a snake_case token and add `orientation` (sexual orientation).
  // Bounding cuts substring FPs; the AMBIGUOUS_TECHNICAL_SUFFIX + UI_ORIENTATION exclusions (below)
  // then clear the token-level FPs boundaries can't (race_id, race_condition, screen_orientation).
  [/(^|_)(gender|ethnicity|ethnic|race|religion|religious|sexual|orientation)(_|$)/, "SPECIAL_CATEGORY", "SENSITIVE_PII", "medium"],
  [/(^|_)(nationality|citizenship)(_|$)/, "NATIONALITY", "SENSITIVE_PII", "medium"],
  // #856: blood_type is genuine PHI — carved out of DESCRIPTOR_SUFFIX_PATTERN's `_type` exclusion
  // (see exclusionReason) so it isn't swallowed the way `record_type`/`email_category` are.
  [/(^|_)blood_?type(_|$)/, "BLOOD_TYPE", "PHI", "high"],
  // #856: word-bound `health` so it matches the concept as a token (mental_health, health_data) and
  // the AMBIGUOUS_TECHNICAL_SUFFIX exclusion then clears health_score/-condition/-count lookalikes.
  [/((^|_)health(_|$)|diagnosis|medical|patient|prescription|(^|_)icd(_|$))/, "HEALTH", "PHI", "high"],
  [/(^|_)name(_|$)/, "NAME?", "PII", "low"], // ambiguous: product/display name — review
  // #233: widened to also catch `tax_number` (`vat_id` was already covered by the `vat`
  // alternative below since it's word-bounded, not literal `tax_id`/`vat`).
  [/(tax_id|tax_number|(^|_)ein(_|$)|(^|_)vat(_|$)|(^|_)nino(_|$))/, "TAX_ID", "SENSITIVE_PII", "medium"],
  // --- Stored credentials/secrets — not PII/PHI/PCI, but its own data-exposure class: a
  // plaintext credential sitting in an app table (readable by any row-level query that isn't
  // locked down) is the M10 headline finding, not the contact PII next to it (ATC dogfood:
  // plaintext `ai_api_key`/`smtp_pass` in `organisations`, readable by any org member via normal
  // RLS). Deliberately narrow: no bare `token` alternative, so single-use capability tokens
  // (invite/share/reset/verify links) never reach these — see the capability-token exclusion
  // below for the one shape that still needs an explicit guard (`password_reset_token`, which
  // contains "password").
  [/(api_?key|client_secret|private_?key|encryption_?key|secret_?key)/, "API_KEY", "SECRET", "high"],
  [/(smtp_pass|(^|_)password(_|$)|(^|_)passwd(_|$))/, "STORED_PASSWORD", "SECRET", "high"],
  [/(access_?token|refresh_?token|auth_?token|session_?token)/, "AUTH_TOKEN", "SECRET", "high"],
];

// Every rule above over-matches on real schemas (validated on ATC — see briefs/audit-modules.md
// M10). These are the observed FP classes: a column *about* an infotype (a descriptor/category
// column, a boolean flag referencing the concept) is not a column *of* that infotype. Checked
// after a dictionary match, before the hit is returned — an excluded name never asserts PII.
const BOOLEAN_FLAG_NAME_PATTERN =
  /(^|_)(is|has|awaiting|needs|requires|pending)_|_(flag|reprompt|required|pending|enabled|requested|consent)(_|$)/;
const INFRA_HEALTH_PATTERN =
  /(^|_)(vendor|service|system|api|db|database|server|infra|upstream|integration|endpoint|app|deployment|pipeline|job|worker|queue)_?health(_|$)/;
// Suffix meaning "a category/type OF the concept," not the concept's value (e.g. email_category,
// address_type). #856: `blood_type` is the one genuine PHI value ending in `_type` — carved out
// below so the exclusion kills `record_type`/`email_category` without swallowing it.
const DESCRIPTOR_SUFFIX_PATTERN = /_(category|type|kind|class)$/;
const DESCRIPTOR_SUFFIX_CARVEOUT = /(^|_)blood_?type$/;
// #856: the ambiguous special-category / health concepts (`race`, `health`, …) are legitimate as a
// token (mental_health, race/ethnicity) but collide with unrelated technical columns — `race_id`
// (an FK), `race_condition` (concurrency), `health_score` (a metric). A clearly-technical suffix on
// one of those infotypes is the FP; word boundaries alone can't catch it (`_id`/`_score` ARE token
// boundaries). Scoped to SPECIAL_CATEGORY/HEALTH so it never suppresses `passport_id`, `ssn_...`, etc.
const AMBIGUOUS_CONCEPT_INFOTYPES = new Set(["SPECIAL_CATEGORY", "HEALTH"]);
const AMBIGUOUS_TECHNICAL_SUFFIX = /_(id|score|condition|count)$/;
// #856: `orientation` genuinely means sexual orientation on HR/dating schemas, but screen/page/
// device/layout orientation is UI furniture — excluded so the bare-`orientation` addition doesn't
// flood every app that stores a display orientation.
const UI_ORIENTATION = /(^|_)(screen|page|device|text|layout|landscape|portrait|display)_orientation(_|$)/;
// #233: an entity's own display name on a table that IS that entity (organizations.name,
// tenants.company_name) is the org's name, not a person's — the NAME/NAME? rules can't tell
// "whose name" a bare `name` column holds without the table it lives on.
const ORG_ENTITY_TABLE_PATTERN = /(^|_)(organi[sz]ations?|orgs?|tenants?|companies|company|workspaces?|teams?)$/;
const NAME_INFOTYPES = new Set(["NAME", "NAME?"]);
// #233: a capability token (invite/share/reset/verify/magic-link) is a single-use authorization
// artifact, not a stored long-lived credential — `password_reset_token` would otherwise match
// STORED_PASSWORD via its "password" substring.
const CAPABILITY_TOKEN_VERB_PATTERN = /(invite|invitation|share|reset|verif|confirm|magic_?link)/;
const CAPABILITY_TOKEN_NOUN_PATTERN = /(token|code|link)/;
const SECRET_INFOTYPES = new Set(["API_KEY", "STORED_PASSWORD", "AUTH_TOKEN"]);

function exclusionReason(column, sqlType, infotype, tableName) {
  if (sqlType && String(sqlType).toLowerCase() === "boolean") {
    return "sql type is boolean — PII/PHI/PCI values aren't booleans, this is a flag referencing the concept";
  }
  if (BOOLEAN_FLAG_NAME_PATTERN.test(column)) return "boolean-flag naming, not a data value";
  if (INFRA_HEALTH_PATTERN.test(column)) return "infra/system health-check naming, not medical health data";
  if (DESCRIPTOR_SUFFIX_PATTERN.test(column) && !DESCRIPTOR_SUFFIX_CARVEOUT.test(column)) {
    return "descriptor suffix — categorizes the concept, isn't the value";
  }
  if (AMBIGUOUS_CONCEPT_INFOTYPES.has(infotype) && AMBIGUOUS_TECHNICAL_SUFFIX.test(column)) {
    return "technical suffix (_id/_score/_condition/_count) on an ambiguous special-category/health term — not the sensitive value";
  }
  if (infotype === "SPECIAL_CATEGORY" && UI_ORIENTATION.test(column)) {
    return "UI display orientation (screen/page/device), not sexual orientation";
  }
  if (NAME_INFOTYPES.has(infotype) && tableName && ORG_ENTITY_TABLE_PATTERN.test(toSnakeCase(tableName))) {
    return "entity display name on an org/tenant/company table — not personal PII";
  }
  if (SECRET_INFOTYPES.has(infotype) && CAPABILITY_TOKEN_VERB_PATTERN.test(column) && CAPABILITY_TOKEN_NOUN_PATTERN.test(column)) {
    return "capability token/link (invite/share/reset/verify) — a single-use authorization artifact, not a stored credential";
  }
  return null;
}

// #233: a bare `number` column only reads as PHONE with table context (a `phone`/`contact`/
// `sms`/`call` table) — on its own it's as likely an order/tracking/account number, so this
// stays out of the name-only RULES dictionary and only fires with that context, at medium
// (review) confidence rather than the high confidence a `phone_number`-named column gets.
const BARE_NUMBER_COLUMN_PATTERN = /^number$/;
const PHONE_CONTEXT_TABLE_PATTERN = /(phone|contact|sms|call|dial)/;

// #233: an opaquely-named column (`value`/`data`/`payload`) on a table that IS a credential/
// config store (BoxyHQ SAML/SSO's `jackson_store.value`) holds an encrypted secret blob a
// name-only matcher otherwise skips entirely — table context is the only signal available.
const OPAQUE_STORE_TABLE_PATTERN = /(_store|_config|_secrets?|_credentials?)$/;
const OPAQUE_STORE_COLUMN_PATTERN = /^(value|data|payload|blob|secret|config)$/;

// #377: denormalizing PII into a jsonb `profile`/`metadata` column instead of first-class columns
// is a common convention (no migration needed to extend — a frequent AI-scaffolded-schema
// shortcut), and a name-only matcher is blind to the nested keys. A jsonb/json column whose name
// matches this denormalization-container vocabulary — on ANY table, unlike the `_store`-scoped
// SECRET rule above — gets a LOW-confidence OPAQUE_JSON_BLOB hit: "review this column's contents
// for nested PII", a flag, never an assertion. Vocabulary rationale: these are the names schemas
// use for catch-all person/entity data containers. Deliberately OUT: bare state/cache/flags names
// (`ui_state`, `feature_flags`) and "any jsonb column" — too aggressive floods every schema that
// legitimately uses jsonb for non-PII settings with noise; this list repeats today's silent miss
// nowhere the container convention applies. Value inspection stays out entirely ("detect, don't
// ask" — names and types only).
const JSON_CONTAINER_TYPE_PATTERN = /^jsonb?$/;
const JSON_CONTAINER_NAME_PATTERN =
  /(^|_)(metadata|profile|details|custom_fields|extra_data|settings|preferences|raw_data|payload|attributes|info)(_|$)/;

// #850: free-text columns (notes/comments/bio/description/body/content) are where regulated data
// hides in real apps, and name-only matching is structurally blind to their VALUES. A text-typed
// column with a narrative-shaped name gets a LOW-confidence FREE_TEXT_REVIEW flag — "review this
// column's contents for unstructured PII/PHI", a flag, never an assertion (mirrors #377's json
// container flag). This is the NAME-based visibility flag so the blind spot appears in the output;
// #855's opt-in semantic pass reasons over names/types/table context but still never reads VALUES,
// so a content-reading (value-sampling) tier remains deliberately out of scope. Type-gated (only
// free-text-shaped types) and vocabulary-scoped so it doesn't flag every string column — still
// FP-prone (an email `body`, a product `description`), which is exactly why it's low-confidence
// review, not a classification. Checked LAST, so any higher-signal dictionary/type hit wins first.
const FREE_TEXT_TYPE_PATTERN = /^(text|character varying|varchar|character|char|citext|string)/;
const FREE_TEXT_NAME_PATTERN = /(^|_)(notes?|comments?|bio|description|body|content|remarks?|memo)(_|$)/;

// Review-flag infotypes are surfaced as "look inside this column", never counted as asserted PII —
// they get their own list in the report and stay out of the asserted headline (#377/#850).
const REVIEW_FLAG_INFOTYPES = new Set(["OPAQUE_JSON_BLOB", "FREE_TEXT_REVIEW"]);

/**
 * @typedef {{infotype: string, category: "PII"|"SENSITIVE_PII"|"PHI"|"PCI"|"SECRET", confidence: "high"|"medium"|"low"}} ClassifyResult
 */

// #936: the dictionary and every exclusion below anchor on snake_case word boundaries
// (`(^|_)…(_|$)`), so a camelCase/PascalCase identifier — the Prisma/Drizzle/quoted-identifier
// convention half the Supabase corpus uses — never presents a boundary and slips through
// entirely: `firstName`, `mobilePhone`, `emailAddress`, `taxId`, `dateOfBirth`, `nationalId`
// all classified NONE on carbon's 154-table ERP schema (measured, docs/design/m10-camelcase-
// tokenization.md). Normalising case boundaries to `_` before matching makes those columns
// behave exactly as their snake_case equivalents would — the exclusions gain the same boundary
// too, so `screenOrientation`/`raceId`/`isPinned` stay suppressed. Standard camel→snake with the
// acronym pass so `taxId`→`tax_id` and `APIKey`→`api_key`.
function toSnakeCase(s) {
  return String(s)
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase();
}

/**
 * Classify a single column by name (and, optionally, its SQL type for the exclusion pass and
 * its table name for the handful of checks that need table context to disambiguate). Never
 * inspects data — name/type/table only. Returns null for no match or an excluded false positive.
 * @param {string} column
 * @param {string} [sqlType] e.g. information_schema.columns.data_type
 * @param {string} [tableName] e.g. information_schema.columns.table_name
 * @returns {ClassifyResult|null}
 */
export function classifyColumn(column, sqlType, tableName) {
  const c = toSnakeCase(column);
  for (const [pattern, infotype, category, confidence] of RULES) {
    if (!pattern.test(c)) continue;
    if (exclusionReason(c, sqlType, infotype, tableName)) return null;
    return { infotype, category, confidence };
  }
  if (tableName) {
    const t = toSnakeCase(tableName);
    if (BARE_NUMBER_COLUMN_PATTERN.test(c) && PHONE_CONTEXT_TABLE_PATTERN.test(t)) {
      return { infotype: "PHONE", category: "PII", confidence: "medium" };
    }
    if (OPAQUE_STORE_COLUMN_PATTERN.test(c) && OPAQUE_STORE_TABLE_PATTERN.test(t)) {
      return { infotype: "OPAQUE_ENCRYPTED_STORE", category: "SECRET", confidence: "medium" };
    }
  }
  // #377: checked AFTER the table-scoped opaque-store rule so a `payload` column on a
  // `*_store`/`*_config` table keeps its higher-signal SECRET classification.
  if (sqlType && JSON_CONTAINER_TYPE_PATTERN.test(String(sqlType).toLowerCase()) && JSON_CONTAINER_NAME_PATTERN.test(c)) {
    return { infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" };
  }
  // #850: last, so any higher-signal dictionary/type/table hit above wins over the free-text flag.
  if (sqlType && FREE_TEXT_TYPE_PATTERN.test(String(sqlType).toLowerCase()) && FREE_TEXT_NAME_PATTERN.test(c)) {
    return { infotype: "FREE_TEXT_REVIEW", category: "PII", confidence: "low" };
  }
  return null;
}

// Severity-weighting: lets a caller (an exposure finding in another module) weight severity by
// WHAT was exposed, not just THAT something was exposed. Category base points, scaled by match
// confidence, summed per distinct infotype on a table. CVV is overridden — PCI-DSS forbids
// storing it post-auth at all, so its presence alone should read Critical.
const CATEGORY_POINTS = { PII: 1, SENSITIVE_PII: 4, PHI: 6, PCI: 6, SECRET: 6 };
const CONFIDENCE_WEIGHT = { high: 1, medium: 0.6, low: 0.3 };
// #376: PIN and track data share CVV's override — all three are PCI-DSS "sensitive
// authentication data", forbidden to store post-authorization under any circumstance.
const INFOTYPE_POINT_OVERRIDES = { CVV: 12, PIN: 12, TRACK_DATA: 12 };

function pointsFor(hit) {
  const base = INFOTYPE_POINT_OVERRIDES[hit.infotype] ?? CATEGORY_POINTS[hit.category];
  return base * CONFIDENCE_WEIGHT[hit.confidence];
}

// Thresholds: a single high-confidence PHI/PCI hit alone scores 6 → "High"; stacking categories
// (e.g. a table with card number + SSN + health data) pushes past 8 → "Critical". A lone
// ambiguous name (NAME?, low confidence) scores 0.3 → "Low". Labels match src/findings.ts's
// Severity enum so a caller can drop `severity` straight into Finding.severity.
function scoreToSeverity(score) {
  if (score >= 8) return "Critical";
  if (score >= 4) return "High";
  if (score >= 1.5) return "Medium";
  if (score > 0) return "Low";
  return "Info";
}

/**
 * Build the per-table data map: table → {columns, infotypes, categories, severityScore,
 * severity, phi, pci}. `columns` matches information_schema.columns shape:
 * {table_name, column_name, data_type}. `resolve` is swappable so classifyWithFallback (below)
 * can merge in semantic hits without duplicating the aggregation logic.
 * @param {{table_name: string, column_name: string, data_type?: string}[]} columns
 * @param {(col: {table_name: string, column_name: string, data_type?: string}) => ClassifyResult|null} [resolve]
 */
export function buildDataMap(columns, resolve = (col) => classifyColumn(col.column_name, col.data_type, col.table_name)) {
  const byTable = new Map();
  for (const col of columns) {
    const hit = resolve(col);
    if (!hit) continue;
    if (!byTable.has(col.table_name)) byTable.set(col.table_name, { columns: [], infotypes: new Map() });
    const t = byTable.get(col.table_name);
    t.columns.push({ column: col.column_name, ...hit });
    if (!t.infotypes.has(hit.infotype)) t.infotypes.set(hit.infotype, hit);
  }

  const map = {};
  for (const [table, t] of byTable) {
    const infotypes = [...t.infotypes.values()];
    const score = infotypes.reduce((sum, h) => sum + pointsFor(h), 0);
    map[table] = {
      columns: t.columns,
      infotypes: infotypes.map((h) => h.infotype),
      categories: [...new Set(infotypes.map((h) => h.category))],
      severityScore: Math.round(score * 10) / 10,
      severity: scoreToSeverity(score),
      phi: infotypes.some((h) => h.category === "PHI"),
      pci: infotypes.some((h) => h.category === "PCI"),
      secret: infotypes.some((h) => h.category === "SECRET"),
    };
  }
  return map;
}

/**
 * Semantic fallback (issue #17 stretch goal, wired by #855) for names the dictionary can't
 * resolve deterministically — obfuscated/custom fields like `contact_handle`, `dob_estimate`.
 * Batches the *names/types only* (never values) of unresolved columns to the injected
 * classifier and expects the same ClassifyResult shape back. The name-based dictionary is
 * ALWAYS the base layer: a dictionary hit is never overridden by a semantic verdict, and a
 * semantic verdict only fills columns the dictionary left null. The default paid/opt-in
 * implementation is createAnthropicSemanticClassifier (below); tests inject fakes so no
 * network call ever runs under `pnpm verify`.
 * @typedef {(columns: {table_name: string, column_name: string, data_type?: string}[]) => Promise<Map<string, ClassifyResult|null>>} SemanticClassifier
 * @param {{table_name: string, column_name: string, data_type?: string}[]} columns
 * @param {SemanticClassifier} [semanticClassifier]
 */
export async function classifyWithFallback(columns, semanticClassifier) {
  if (!semanticClassifier) return buildDataMap(columns);
  const unresolved = columns
    .filter((col) => !classifyColumn(col.column_name, col.data_type, col.table_name))
    .map((col) => ({ table_name: col.table_name, column_name: col.column_name, data_type: col.data_type }));
  if (unresolved.length === 0) return buildDataMap(columns);

  const semanticHits = await semanticClassifier(unresolved);
  return buildDataMap(columns, (col) => {
    const dictHit = classifyColumn(col.column_name, col.data_type, col.table_name);
    if (dictHit) return dictHit;
    const semanticHit = semanticHits.get(`${col.table_name}.${col.column_name}`);
    return semanticHit ? { ...semanticHit, source: "semantic" } : null;
  });
}

// --- #855: the real semantic classifier — PAID, OPT-IN ONLY -------------------------------
//
// Gated twice: the CLI only builds it when BOTH `--semantic` is passed AND ANTHROPIC_API_KEY is
// set (resolveSemanticClassifier). Absent either, no classifier exists and classifyWithFallback
// takes the name-based-only path — byte-identical to pre-#855 behavior, zero network calls.
// Privacy posture matches the rest of this module ("detect, don't ask"): only column NAMES,
// declared TYPES, table names, and sibling column names are sent — never data values. A semantic
// verdict is a review-tier guess, never an assertion: confidence is clamped to low/medium ("high"
// stays reserved for deterministic dictionary matches), and dataMapToFindings tags each
// semantic-sourced column so the report shows which classifications came from the LLM pass.

export const DEFAULT_SEMANTIC_MODEL = "claude-sonnet-5";
const ANTHROPIC_VERSION = "2023-06-01";
const SEMANTIC_BATCH_SIZE = 100;
const SEMANTIC_MAX_SIBLINGS = 30;
const SEMANTIC_CATEGORIES = new Set(["PII", "SENSITIVE_PII", "PHI", "PCI", "SECRET"]);
const SEMANTIC_INFOTYPE_SHAPE = /^[A-Z0-9_?]{2,64}$/;

const SEMANTIC_SYSTEM_PROMPT = `You are a data-classification reviewer inside a database-schema audit (PII/PHI/PCI/stored-secret detection). You receive a JSON array of columns a deterministic name-dictionary could NOT classify. For each column, decide — from its name, declared SQL type, table name, and sibling column names ONLY (no data values are available) — whether it likely stores personal data (PII), sensitive personal data (SENSITIVE_PII), health data (PHI), payment-card data (PCI), or a stored credential/secret (SECRET). Pay particular attention to obfuscated or nonstandard names (contact_handle, dob_estimate), generically-named columns whose table context implies regulated data, and free-text/json/unknown-typed columns whose name+context suggests they hold such data.

Respond with ONLY a JSON array — no prose, no markdown fences. Include one entry per input column that likely holds regulated data and OMIT columns that do not:
[{"table": "<table_name>", "column": "<column_name>", "infotype": "<UPPER_SNAKE label, e.g. EMAIL, DOB, HEALTH>", "category": "PII|SENSITIVE_PII|PHI|PCI|SECRET", "confidence": "low|medium"}]

Be conservative — this audit treats a semantic verdict as a review flag, never an assertion. When in doubt, omit the column or use "low".`;

// Strict-shape parse of the model's JSON verdicts. Anything malformed at the envelope level
// throws (an opted-in pass that produced garbage must fail loud, not silently classify nothing);
// individual entries outside the allowed shape are dropped — a bad verdict never enters the map.
function parseSemanticVerdicts(text) {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start < 0 || end <= start) throw new Error(`semantic classifier: model response contained no JSON array: ${text.slice(0, 200)}`);
  const entries = JSON.parse(text.slice(start, end + 1));
  if (!Array.isArray(entries)) throw new Error("semantic classifier: model response was not a JSON array");
  const hits = new Map();
  for (const e of entries) {
    if (!e || typeof e.table !== "string" || typeof e.column !== "string") continue;
    if (!SEMANTIC_CATEGORIES.has(e.category)) continue;
    if (typeof e.infotype !== "string" || !SEMANTIC_INFOTYPE_SHAPE.test(e.infotype)) continue;
    // "high" is reserved for deterministic dictionary matches — a semantic guess caps at medium,
    // and anything other than an explicit medium/high coerces to low (the conservative floor).
    const confidence = e.confidence === "medium" || e.confidence === "high" ? "medium" : "low";
    hits.set(`${e.table}.${e.column}`, { infotype: e.infotype, category: e.category, confidence });
  }
  return hits;
}

/**
 * Builds a SemanticClassifier that calls the Anthropic Messages API via built-in fetch (no SDK —
 * deliberately dependency-free, see #855). `allColumns` supplies sibling-column context; `fetchImpl`
 * is injectable so tests never touch the network. Throws on any API/parse failure — an opted-in
 * semantic pass that can't run is an error, never a silent downgrade to name-based-only.
 * @param {{apiKey: string, model?: string, allColumns?: {table_name: string, column_name: string}[], fetchImpl?: typeof fetch, baseUrl?: string}} opts
 * @returns {SemanticClassifier & {model: string}}
 */
export function createAnthropicSemanticClassifier({
  apiKey,
  model = DEFAULT_SEMANTIC_MODEL,
  allColumns = [],
  fetchImpl = globalThis.fetch,
  baseUrl = "https://api.anthropic.com",
} = {}) {
  if (!apiKey) throw new Error("createAnthropicSemanticClassifier requires an apiKey — the semantic pass never runs without one (#855)");
  const siblingsByTable = new Map();
  for (const col of allColumns) {
    if (!siblingsByTable.has(col.table_name)) siblingsByTable.set(col.table_name, []);
    siblingsByTable.get(col.table_name).push(col.column_name);
  }

  const classifier = async (unresolved) => {
    const hits = new Map();
    for (let i = 0; i < unresolved.length; i += SEMANTIC_BATCH_SIZE) {
      const items = unresolved.slice(i, i + SEMANTIC_BATCH_SIZE).map((col) => ({
        table: col.table_name,
        column: col.column_name,
        sql_type: col.data_type ?? null,
        sibling_columns: (siblingsByTable.get(col.table_name) ?? [])
          .filter((c) => c !== col.column_name)
          .slice(0, SEMANTIC_MAX_SIBLINGS),
      }));
      const res = await fetchImpl(`${baseUrl}/v1/messages`, {
        method: "POST",
        headers: { "x-api-key": apiKey, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json" },
        body: JSON.stringify({
          model,
          max_tokens: 8192,
          system: SEMANTIC_SYSTEM_PROMPT,
          messages: [{ role: "user", content: JSON.stringify(items) }],
        }),
      });
      if (!res.ok) throw new Error(`semantic classifier: Anthropic API ${res.status} — ${await res.text()}`);
      const msg = await res.json();
      if (msg.stop_reason === "refusal") throw new Error("semantic classifier: the model refused the classification request");
      const text = (msg.content ?? [])
        .filter((b) => b.type === "text")
        .map((b) => b.text)
        .join("");
      for (const [key, hit] of parseSemanticVerdicts(text)) hits.set(key, hit);
    }
    return hits;
  };
  classifier.model = model;
  return classifier;
}

/**
 * The CLI's double gate (#855): returns the fetch-based classifier ONLY when the run explicitly
 * opted in with `--semantic` AND ANTHROPIC_API_KEY is set. Anything less returns null and the
 * caller takes exactly today's name-based-only path — no network call is possible. Opting in
 * without a key is disclosed on stderr (fail loud) but still downgrades per the product decision
 * that the free tier must never require a key. Model: `--semantic-model <id>`, else
 * PII_SEMANTIC_MODEL, else claude-sonnet-5.
 * @param {{argv?: string[], env?: Record<string, string|undefined>, allColumns?: {table_name: string, column_name: string}[]}} opts
 */
export function resolveSemanticClassifier({ argv = process.argv, env = process.env, allColumns = [] } = {}) {
  if (!argv.includes("--semantic")) return null;
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error("⚠ --semantic requested but ANTHROPIC_API_KEY is not set — semantic pass skipped; name-based classification only (#855).");
    return null;
  }
  const i = argv.indexOf("--semantic-model");
  const flagModel = i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : undefined;
  return createAnthropicSemanticClassifier({ apiKey, model: flagModel ?? env.PII_SEMANTIC_MODEL ?? DEFAULT_SEMANTIC_MODEL, allColumns });
}

// #436: the data-map → report-schema Finding[] mapper, shared by the schema and live paths, so
// M10's classification reaches the engagement doc instead of dying in a console summary. One
// finding per PII/PHI/PCI-bearing table; severity is the table's scoreToSeverity label;
// confidence is always "Review" — name/type classification is heuristic on BOTH tiers (the tier
// changes what the schema evidence is, not the classification method), so a hit is a triage
// input, never an assertion. #377's OPAQUE_JSON_BLOB review flags are surfaced as a distinct
// "review for nested PII" sentence, never blended into the classified-column claim.
const SEVERITY_VALUE = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
const PCI_NEVER_STORE = new Set(["CVV", "PIN", "TRACK_DATA"]);

/**
 * @param {ReturnType<typeof buildDataMap>} dataMap
 * @param {{tier: "schema"|"live"}} opts
 */
export function dataMapToFindings(dataMap, { tier }) {
  // #853: state the scope so the divergence between tiers is visible, not silent — the live path
  // reads information_schema (includes views) but only the `public` schema; the static path parses
  // CREATE TABLE + ALTER TABLE ADD COLUMN but not views/matviews/generated columns.
  const source =
    tier === "live"
      ? "live information_schema.columns inventory (read-only), public schema only — auth/storage/other schemas not inventoried"
      : "static migration-SQL schema parse (no DB connection), CREATE TABLE + ALTER TABLE ADD COLUMN columns only — views, materialized views, and generated columns are not parsed on this tier";
  const tables = Object.keys(dataMap).sort(
    (a, b) => dataMap[b].severityScore - dataMap[a].severityScore || a.localeCompare(b),
  );
  return tables.map((table, i) => {
    const t = dataMap[table];
    const asserted = t.columns.filter((c) => !REVIEW_FLAG_INFOTYPES.has(c.infotype));
    const reviewFlags = t.columns.filter((c) => REVIEW_FLAG_INFOTYPES.has(c.infotype));
    const jsonFlags = reviewFlags.filter((c) => c.infotype === "OPAQUE_JSON_BLOB");
    const freeTextFlags = reviewFlags.filter((c) => c.infotype === "FREE_TEXT_REVIEW");
    const neverStore = t.infotypes.filter((x) => PCI_NEVER_STORE.has(x));
    const compliance = [
      t.phi && "PHI — HIPAA applicability",
      t.pci && "PCI-DSS cardholder/sensitive-authentication data",
      t.secret && "stored credentials/secrets readable by any query path that reaches the table",
    ].filter(Boolean);
    return {
      id: `M10-${String(i + 1).padStart(2, "0")}`,
      title: asserted.length
        ? `Table \`${table}\` holds ${t.categories.join("/")} data (${[...new Set(asserted.map((c) => c.infotype))].join(", ")})`
        : freeTextFlags.length && !jsonFlags.length
          ? `Table \`${table}\` has free-text column(s) to review for unstructured PII/PHI`
          : jsonFlags.length && !freeTextFlags.length
            ? `Table \`${table}\` has JSON container column(s) to review for nested PII`
            : `Table \`${table}\` has free-text and JSON container column(s) to review for PII`,
      severity: t.severity,
      confidence: "Review",
      category: "Data classification",
      taxonomy: "M10 — Data classification (PII/PHI/PCI)",
      location: table,
      status: "Open",
      evidence: [
        `${source}; name/type classification only — no values were read.`,
        asserted.length
          ? `Classified columns: ${asserted.map((c) => `${c.column} → ${c.infotype} (${c.category}, ${c.confidence}${c.source === "semantic" ? ", semantic" : ""})`).join("; ")}.`
          : "",
        jsonFlags.length
          ? `Review for nested PII (flagged, not asserted — #377): ${jsonFlags.map((c) => c.column).join(", ")} — denormalization-container json column(s); inspect their keys.`
          : "",
        freeTextFlags.length
          ? `Review for unstructured PII/PHI (flagged, not asserted — #850): ${freeTextFlags.map((c) => c.column).join(", ")} — free-text column(s) whose values a name-only scan can't see; inspect for names/SSNs/health details.`
          : "",
        `Severity score ${t.severityScore} → ${t.severity}.`,
      ]
        .filter(Boolean)
        .join(" "),
      impact: [
        `Any over-broad read path (RLS gap, leaked service key, injectable query) on \`${table}\` exposes ${t.categories.join("/")} data.`,
        compliance.length ? `Compliance surface: ${compliance.join("; ")}.` : "",
        neverStore.length
          ? `Stores PCI sensitive authentication data (${neverStore.join(", ")}) — PCI-DSS forbids storing it post-authorization at all, so its presence is a violation independent of exposure.`
          : "",
      ]
        .filter(Boolean)
        .join(" "),
      fix: [
        "Confirm each classified column is genuinely needed and that the table's RLS/grants scope reads to the owning tenant/user.",
        neverStore.length ? "Remove the sensitive-authentication-data column(s) — they may not be stored post-authorization under PCI-DSS." : "",
        t.secret ? "Move stored credentials to a secret manager or encrypt them with keys the DB role cannot read." : "",
        jsonFlags.length ? "Inspect the flagged JSON container(s); promote any nested PII to first-class columns so it is classified and protected explicitly." : "",
        freeTextFlags.length ? "Review the flagged free-text column(s) for unstructured PII/PHI; a content-classification pass or structured fields make regulated data visible and protectable." : "",
      ]
        .filter(Boolean)
        .join(" "),
      value: SEVERITY_VALUE[t.severity] ?? 1,
      ease: 3,
      safety: 4,
      mechanical: true,
      precisionTier: "review",
      // #459: lets the renderer give review flags a distinct "review for nested PII" section
      // instead of interleaving them with asserted classification findings.
      reviewFlagOnly: asserted.length === 0 && reviewFlags.length > 0,
      reviewFlagColumns: reviewFlags.map((c) => c.column),
    };
  });
}

function flagPath(flag) {
  const i = process.argv.indexOf(flag);
  if (i < 0) return null;
  const value = process.argv[i + 1];
  if (!value || value.startsWith("--")) {
    console.error(`${flag} requires a file path`);
    process.exit(1);
  }
  return value;
}

// --out <path> (#436): write the report-schema Finding[] the orchestrator's M10 probe captures
// (run-audit --findings-out). No --out → console summary only, exactly as before.
// `extra` (#1043) carries the protection verdict rows, which are per-COLUMN judgments rather than
// per-table classifications and so are not derivable from the data map alone.
function writeFindingsOut(dataMap, tier, extra) {
  const outPath = flagPath("--out");
  if (!outPath) return;
  const findings = [...dataMapToFindings(dataMap, { tier }), ...extra];
  writeFileSync(outPath, `${JSON.stringify(findings, null, 2)}\n`);
  console.log(`\n${findings.length} report-schema finding(s) → ${outPath}`);
}

// --data-map-out <path> (#1049): the table→data-class map itself, which the orchestrator feeds to
// the assembler so EVERY module's severities are weighted by the sensitivity of the data they
// touch. Written separately from --out because it is an input to other modules' findings, not a
// finding: the per-table classification findings are a projection of it, not a substitute for it.
function writeDataMapOut(dataMap) {
  const outPath = flagPath("--data-map-out");
  if (!outPath) return;
  writeFileSync(outPath, `${JSON.stringify(dataMap, null, 2)}\n`);
  console.log(`Data map (${Object.keys(dataMap).length} classified table(s)) → ${outPath}`);
}

// Each case is [column, expectedCategory (null = no match), expectedConfidence, sqlType,
// tableName] — sqlType/tableName are only needed by the exclusion/table-context checks below
// and default to undefined when omitted.
function selftest() {
  const cases = [
    ["email", "PII", "high"],
    ["customer_ssn", "SENSITIVE_PII", "high"],
    ["date_of_birth", "PII", "high"],
    ["card_last4", "PCI", "high"],
    ["cvv", "PCI", "high"],
    ["passport_number", "SENSITIVE_PII", "high"],
    ["medical_record_number", "PHI", "high"],
    ["genetic_marker", "SENSITIVE_PII", "high"],
    ["product_name", "PII", "low"],
    ["created_at", null, null],
    ["tenant_id", null, null],
    // named FP cases (issue #17 acceptance)
    ["email_category", null, null],
    ["awaiting_dob_reprompt", null, null],
    ["vendor_health", null, null],
    // #233: tax-ID under-matching
    ["tax_number", "SENSITIVE_PII", "medium"],
    ["vat_id", "SENSITIVE_PII", "medium"],
    // #233: stored credentials/secrets — the ATC dogfood must-not-miss case
    ["ai_api_key", "SECRET", "high"],
    ["smtp_pass", "SECRET", "high"],
    ["access_token", "SECRET", "high"],
    // #233: capability tokens are NOT stored credentials
    ["password_reset_token", null, null, undefined],
    ["invite_token", null, null],
    ["share_token", null, null],
    // #233: org/tenant/company entity-name suppression (table context required)
    ["name", "PII", "low", undefined, "profiles"], // ambiguous elsewhere — still NAME?
    ["name", null, null, undefined, "organizations"],
    ["company_name", null, null, undefined, "tenants"],
    // #233: bare `number` only reads as phone with table context
    ["number", null, null, undefined, "orders"],
    ["number", "PII", "medium", undefined, "contact_numbers"],
    // #233: opaquely-named encrypted secret store (BoxyHQ jackson_store.value)
    ["value", null, null, undefined, "widgets"],
    ["value", "SECRET", "medium", undefined, "jackson_store"],
    // #376: PCI sensitive auth data — PIN block and track/magstripe data
    ["pin_block", "PCI", "high"],
    ["track2", "PCI", "high"],
    ["is_pinned", null, null],
    // #378: HIPAA device/vehicle/image identifiers
    ["mac_address", "SENSITIVE_PII", "medium"],
    ["license_plate", "PII", "medium"],
    ["avatar_url", "PII", "medium"],
    ["has_photo", null, null, "boolean"],
    // #379: generic national/government ID — and bare/FK `id` columns stay out
    ["national_id", "SENSITIVE_PII", "medium"],
    ["id", null, null],
    ["user_id", null, null],
    // #377: jsonb denormalization containers are review-flagged at low confidence; a jsonb
    // column outside the vocabulary, or a vocabulary name on a non-json type, stays silent
    ["profile", "PII", "low", "jsonb", "users"],
    ["metadata", "PII", "low", "jsonb"],
    ["ui_state", null, null, "jsonb"],
    ["profile", null, null, "text"],
    // #850: free-text columns are review-flagged (low) only on a text-shaped type
    ["case_notes", "PII", "low", "text"],
    ["comment", "PII", "low", "varchar"],
    ["bio", "PII", "low", "text"],
    ["notes", null, null], // no type → free-text gate can't fire
    ["notes", null, null, "integer"], // non-text type is not a free-text column
    ["title", null, null, "text"], // outside the narrative vocabulary
    // #856: blood_type PHI (carved out of the _type descriptor exclusion)
    ["blood_type", "PHI", "high"],
    ["patient_blood_type", "PHI", "high"],
    // #856: new dictionary concepts
    ["salary", "SENSITIVE_PII", "medium"],
    ["compensation", "SENSITIVE_PII", "medium"],
    ["age", "PII", "low"],
    ["mothers_maiden_name", "SENSITIVE_PII", "high"],
    ["maiden_name", "SENSITIVE_PII", "high"],
    ["security_question", "SENSITIVE_PII", "high"],
    ["security_answer", "SENSITIVE_PII", "high"],
    ["orientation", "SENSITIVE_PII", "medium"],
    // #856: over-broad-regex FP guards (word boundary + technical-suffix / UI-orientation exclusions)
    ["health_score", null, null],
    ["race_id", null, null],
    ["race_condition", null, null],
    ["screen_orientation", null, null],
    ["page_count", null, null], // age is token-bounded, so this is not AGE
    ["usage", null, null], // age is token-bounded, so this is not AGE
  ];
  let ok = 0;
  for (const [col, cat, conf, sqlType, tableName] of cases) {
    const r = classifyColumn(col, sqlType, tableName);
    const pass = cat === null ? r === null : r && r.category === cat && r.confidence === conf;
    const label = tableName ? `${tableName}.${col}` : col;
    console.log(`${pass ? "PASS" : "FAIL"}  ${label} → ${r ? r.category + "/" + r.confidence : "none"}`);
    if (pass) ok++;
  }
  console.log(`\n${ok}/${cases.length} passed`);
  process.exit(ok === cases.length ? 0 : 1);
}

// #853: scope disclosure printed at the end of every run so a reader never mistakes the tier's
// coverage limits for a clean bill of health.
const SCOPE_NOTE = {
  live: "Scope: public schema only — auth/storage/other schemas were not inventoried (#853).",
  schema: "Scope: CREATE TABLE + ALTER TABLE ADD COLUMN columns only — views, materialized views, and generated columns are not parsed on the static tier (#853).",
};

function report(cols, dataMap, { tier = "schema", unknownType = [], semanticModel = null } = {}) {
  const tables = Object.keys(dataMap);
  // #377/#850: review-flag hits ("look inside this column") are not asserted PII — they get their
  // own lists below and stay out of the asserted headline count.
  const reviewFlags = tables.flatMap((t) =>
    dataMap[t].columns.filter((c) => REVIEW_FLAG_INFOTYPES.has(c.infotype)).map((c) => ({ ref: `${t}.${c.column}`, infotype: c.infotype })),
  );
  const hitCount = tables.reduce((n, t) => n + dataMap[t].columns.length, 0) - reviewFlags.length;
  const byCat = {};
  for (const t of tables) for (const c of dataMap[t].categories) byCat[c] = (byCat[c] || 0) + 1;

  console.log(`Scanned ${cols.length} columns. PII-bearing columns: ${hitCount} across ${tables.length} tables.`);
  console.log("Tables touching each category:", JSON.stringify(byCat));
  console.log("\nBy severity:");
  for (const t of tables.sort((a, b) => dataMap[b].severityScore - dataMap[a].severityScore)) {
    console.log(`  ${t} → ${dataMap[t].severity} (${dataMap[t].severityScore}): ${dataMap[t].infotypes.join(", ")}`);
  }
  const jsonRefs = reviewFlags.filter((f) => f.infotype === "OPAQUE_JSON_BLOB").map((f) => f.ref);
  const freeTextRefs = reviewFlags.filter((f) => f.infotype === "FREE_TEXT_REVIEW").map((f) => f.ref);
  if (jsonRefs.length) {
    console.log(`\nReview for nested PII — ${jsonRefs.length} JSON container column(s), flagged not asserted (#377):`);
    for (const f of jsonRefs) console.log(`  ${f} — denormalization-container name on a json/jsonb column; inspect its keys for nested PII`);
  }
  if (freeTextRefs.length) {
    console.log(`\nReview for unstructured PII/PHI — ${freeTextRefs.length} free-text column(s), flagged not asserted (#850):`);
    for (const f of freeTextRefs) console.log(`  ${f} — narrative-shaped free-text column; a name-only scan can't see its values, inspect for names/SSNs/health details`);
  }
  // #855: when the opt-in semantic pass ran, say so — including a zero-hit run, so a reader can
  // tell "LLM reviewed the unresolved names and classified nothing" apart from "never ran".
  if (semanticModel) {
    const semanticRefs = tables.flatMap((t) =>
      dataMap[t].columns.filter((c) => c.source === "semantic").map((c) => `${t}.${c.column} → ${c.infotype} (${c.category}, ${c.confidence})`),
    );
    console.log(`\nSemantic pass (${semanticModel}) reviewed the dictionary-unresolved column names/types — no data values were sent (#855). ${semanticRefs.length} column(s) classified semantically (review-tier, never asserted):`);
    for (const ref of semanticRefs) console.log(`  ${ref}`);
  }
  // #851: fail loud — columns whose SQL type isn't recognized were classified by NAME only, so the
  // type-based signals that couldn't apply are visible rather than the columns silently vanishing.
  if (unknownType.length) {
    console.log(`\n⚠ ${unknownType.length} column(s) had an unrecognized SQL type (enum/custom/char/money/xml/array) — classified by NAME only; jsonb-container and boolean-flag signals could not apply (#851):`);
    for (const c of unknownType) console.log(`  ${c.table_name}.${c.column_name} (type ${c.data_type})`);
  }
  console.log(`\n${SCOPE_NOTE[tier]}`);
  return dataMap;
}

// #1043 — the connected tier's PROTECTION inputs, the facts src/pii-protection-review.ts needs to
// turn "this column holds PII" into "this column holds PII and anyone with the anon key can read
// it". Three read-only catalog reads; no data value is ever selected, so the privacy-safe property
// of M10 is unchanged.
//
// exposedSchemas stays empty on this path BY CONSTRUCTION, not by omission: the live inventory only
// ever reads the `public` schema (SCOPE_NOTE.live), and `public` is PostgREST's default exposure, so
// no additional exposed schema is observable from what was inventoried. Table-level exposure carries
// the whole signal here.
//
// Exported so the catalog-rows → ExposureFacts transformation is testable against an injected `sql`
// without a database: the connected tier is the one Harvey sells this check on, and #357's "only
// ever exercised in its failure path" is exactly how an unverified claim survives.
/** @param {(strings: TemplateStringsArray, ...values: unknown[]) => Promise<Record<string, unknown>[]>} sql */
export async function gatherProtectionFacts(sql) {
  const tables =
    await sql`SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`;
  const grants =
    await sql`SELECT DISTINCT table_name FROM information_schema.role_table_grants WHERE table_schema = 'public' AND grantee IN ('anon', 'authenticated') AND privilege_type = 'SELECT'`;
  // pgsodium's transparent-column-encryption view is the only encryption-at-rest signal a catalog
  // read can see. Its columns are checked before it is selected from, rather than assumed: the view
  // shape varies by pgsodium version, and an absent/unreadable view must degrade to "no encryption
  // observed" (disclosed in M10-PROT-00) instead of failing the whole classification run.
  const maskingCols =
    await sql`SELECT column_name FROM information_schema.columns WHERE table_schema = 'pgsodium' AND table_name = 'masking_rule'`;
  const maskingReadable = ["relname", "attname"].every((c) => maskingCols.some((r) => r.column_name === c));
  const masked = maskingReadable ? await sql`SELECT relname AS table_name, attname AS column_name FROM pgsodium.masking_rule` : [];

  const clientReadable = new Set(grants.map((g) => g.table_name));
  const autoExposedTables = tables.filter((t) => !t.rls_enabled && clientReadable.has(t.table_name)).map((t) => `public.${t.table_name}`);
  return {
    facts: { exposedSchemas: [], autoExposedTables },
    encrypted: new Set(masked.map((m) => `${m.table_name}.${m.column_name}`)),
    detail: `Read ${tables.length} public table(s): ${clientReadable.size} carry an anon/authenticated SELECT grant and ${autoExposedTables.length} of those also have RLS disabled (anon-reachable). Encryption at rest: ${maskingReadable ? `pgsodium.masking_rule listed ${masked.length} encrypted column(s)` : "no readable pgsodium.masking_rule view, so no column was credited as encrypted at rest"}.`,
  };
}

// #1043 — turns the classification into a per-column protection VERDICT, or states that no verdict
// was made. Review-flagged columns (free-text / JSON containers) are excluded: they are candidates
// for inspection, not asserted classifications, and asserting "unprotected PII" over one would
// price a maybe as a fact. Their exclusion is stated in the M10-PROT-00 row.
function protectionReview(dataMap, protection, tier) {
  if (!protection) {
    const reason =
      tier === "schema"
        ? "this run classified a static schema (--schema), which carries no RLS state, no grants and no encryption configuration"
        : "no protection facts were gathered on this run";
    console.log(`\nPII protection: NOT verified — ${reason} (#1043).`);
    return [piiProtectionScope({ assessed: false, reason })];
  }
  const columns = Object.entries(dataMap).flatMap(([table, t]) =>
    t.columns
      .filter((c) => !REVIEW_FLAG_INFOTYPES.has(c.infotype))
      .map((c) => ({
        schema: "public",
        table,
        column: c.column,
        category: c.category,
        infotype: c.infotype,
        encrypted: protection.encrypted.has(`${table}.${c.column}`),
      })),
  );
  const findings = piiProtectionFindings(columns, protection.facts);
  console.log(`\nPII protection verified against the live database (#1043): ${columns.length} asserted column(s) checked, ${findings.length} unprotected.`);
  for (const f of findings) console.log(`  ${f.location}`);
  return [piiProtectionScope({ assessed: true, detail: protection.detail, columnsChecked: columns.length, unprotected: findings.length }), ...findings];
}

// #855: the shared classify → report → emit tail for both CLI tiers. The semantic pass slots in
// here (behind resolveSemanticClassifier's double gate) so live and schema runs get it identically.
async function classifyReportAndEmit(cols, { tier, unknownType = [], protection = null }) {
  const semantic = resolveSemanticClassifier({ allColumns: cols });
  const dataMap = await classifyWithFallback(cols, semantic ?? undefined);
  report(cols, dataMap, { tier, unknownType, semanticModel: semantic?.model ?? null });
  writeFindingsOut(dataMap, tier, protectionReview(dataMap, protection, tier));
  writeDataMapOut(dataMap);
}

async function inventory() {
  const { default: postgres } = await import("postgres");
  const sql = postgres(process.env.SUPABASE_DB_URL, { max: 1, idle_timeout: 5 });
  const cols =
    await sql`SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position`;
  const protection = await gatherProtectionFacts(sql);
  await sql.end();
  await classifyReportAndEmit(cols, { tier: "live", protection });
}

/**
 * Classifies every column declared in migration SQL text via src/migration-sql-parse.ts's
 * parseClassifiableColumns — CREATE TABLE (#250) plus ALTER TABLE ADD COLUMN (#852), including
 * columns whose type is outside the recognized SQL_TYPES allow-list (enum/custom/char/…, #851),
 * which are classified by NAME and returned in `unknownType` so the caller can disclose them rather
 * than drop them silently. Under-extract-rather-than-mis-extract: a shape it doesn't recognize
 * yields fewer columns, never a wrong one.
 * @param {string} sql concatenated migration SQL (one or more files)
 * @returns {{columns: {table_name: string, column_name: string, data_type?: string}[], dataMap: ReturnType<typeof buildDataMap>, unknownType: {table_name: string, column_name: string, data_type?: string}[]}}
 */
export function classifyMigrationSql(sql) {
  const { columns, unknownType } = parseClassifiableColumns(sql);
  const all = [...columns, ...unknownType];
  return { columns: all, dataMap: buildDataMap(all), unknownType };
}

/**
 * Classifies a schema.prisma file's declared models directly via the fallback parser (src/prisma-
 * schema-parse.ts), bypassing any Prisma-CLI attempt — the CLI-independent entry point so a test
 * (and CI, with no target Prisma install anywhere) proves the fallback path itself, not just the
 * CLI happy path (#758). columnsFromPrismaSchema (below) is what the real --schema CLI path calls,
 * which tries the CLI first and falls back to this same parser.
 * @param {string} schema raw schema.prisma text
 * @returns {{columns: {table_name: string, column_name: string, data_type?: string}[], dataMap: ReturnType<typeof buildDataMap>}}
 */
export function classifyPrismaSchema(schema) {
  const columns = parsePrismaSchema(schema);
  return { columns, dataMap: buildDataMap(columns) };
}

// #758: the schema.prisma's own project root — Prisma resolves relative to the directory the
// schema lives in, or its parent when the schema sits at the conventional `prisma/schema.prisma`
// location — that's where a target's own `prisma` devDependency would be installed.
function prismaProjectRoot(schemaPath) {
  const dir = dirname(schemaPath);
  return basename(dir) === "prisma" ? dirname(dir) : dir;
}

// Runs the target's OWN locally-installed prisma CLI — never a global or network install — to emit
// the SQL Prisma itself would generate to create this schema from empty, so it feeds the SAME
// CREATE TABLE parser (parseColumns) every SQL-schema target goes through: a Prisma-native table/
// column mapping (@@map/@map, relation scalars resolved to their FK column) beats re-deriving it.
// Returns null (never throws) when the target has no local prisma CLI — the caller falls back to
// the schema.prisma model/field parser instead of failing the whole classification.
function prismaSchemaToSql(schemaPath) {
  const bin = join(prismaProjectRoot(schemaPath), "node_modules", ".bin", process.platform === "win32" ? "prisma.cmd" : "prisma");
  if (!existsSync(bin)) return null;
  try {
    return execFileSync(bin, ["migrate", "diff", "--from-empty", "--to-schema-datamodel", schemaPath, "--script"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

// Columns for a schema.prisma target: the target's local Prisma CLI generating SQL (reusing the
// SQL parser, which now surfaces enum/custom columns via unknownType — #851/#854) when available,
// else the fallback DSL parser (#758) — either way the same {table_name, column_name, data_type}
// shape a SQL-schema target's columns already have, in the {columns, unknownType} envelope.
function columnsFromPrismaSchema(schemaPath) {
  const sql = prismaSchemaToSql(schemaPath);
  if (sql) return parseClassifiableColumns(sql);
  return { columns: parsePrismaSchema(readFileSync(schemaPath, "utf8")), unknownType: [] };
}

// Reads every *.sql file under `target` (sorted, so migrations apply in filename order) if it's a
// directory, or `target` itself if it's a single .sql file — the same shape src/cli/dry-run.ts's
// readMigrations uses for supabase/migrations/. Recursive (#299): Prisma's migration.sql files
// live one directory deeper than Supabase's (prisma/migrations/<timestamp_name>/migration.sql,
// not supabase/migrations/<timestamp>.sql flat) — a non-recursive readdir silently finds nothing
// there and a Prisma target reads as "no schema input" instead of "found 0 columns", which is a
// different, worse failure than the parser under-extracting.
function readSchemaSql(target) {
  const st = statSync(target);
  if (st.isFile()) return readFileSync(target, "utf8");
  return readdirSync(target, { recursive: true })
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(target, f), "utf8"))
    .join("\n\n");
}

// #770: every argv entry after --schema up to the next --flag is a target — the M10 probe
// (src/audit-runners.ts) passes more than one when its schema DDL was discovered scattered across
// multiple unconventional locations, so nothing it found is dropped for lack of a single-path CLI.
// A single target (the common case) behaves exactly as before.
function schemaTargets() {
  const start = process.argv.indexOf("--schema") + 1;
  const targets = [];
  for (let i = start; i < process.argv.length && !process.argv[i].startsWith("--"); i++) targets.push(process.argv[i]);
  return targets;
}

// #758: a `.prisma` target is Prisma DSL, not SQL — classified via columnsFromPrismaSchema
// (CLI-generated SQL, falling back to the schema.prisma parser). Returns {columns, unknownType},
// the same envelope parseClassifiableColumns produces for a SQL target (#851/#852).
function columnsForTarget(target) {
  if (target.endsWith(".prisma")) return columnsFromPrismaSchema(target);
  return parseClassifiableColumns(readSchemaSql(target));
}

async function classifyFromSchema() {
  const targets = schemaTargets();
  const missing = targets.filter((t) => !existsSync(t));
  if (targets.length === 0 || missing.length) {
    const detail = missing.length ? ` — ${missing.join(", ")} does not exist` : "";
    console.error(`Usage: pii-classify --schema <path> [<path> ...] (each a supabase/migrations dir, a single .sql file, or a schema.prisma file)${detail}`);
    process.exit(1);
  }
  const results = targets.map(columnsForTarget);
  const columns = results.flatMap((r) => r.columns);
  const unknownType = results.flatMap((r) => r.unknownType);
  const all = [...columns, ...unknownType];
  if (all.length === 0) {
    console.error(`No columns found via ${targets.join(", ")} — check the path(s) (expects supabase/migrations/*.sql shape, a standalone schema.sql with CREATE TABLE, or a schema.prisma with model declarations).`);
    process.exit(1);
  }
  await classifyReportAndEmit(all, { tier: "schema", unknownType });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes("--selftest")) selftest();
  else if (process.argv.includes("--schema")) classifyFromSchema();
  else inventory();
}
