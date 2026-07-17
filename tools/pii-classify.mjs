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
//
// The --schema path parses `CREATE TABLE` columns straight out of migration SQL (a directory of
// *.sql files, or a single .sql file) via src/migration-sql-parse.ts's parseColumns — the same
// under-extract-rather-than-mis-extract parser the M1 detect-deeper classifiers use — so this
// runs the identical classifier over source-only engagements instead of needing a live DB.
// Requires `tsx` (the `pnpm pii-classify` script) rather than plain `node`, since it imports a
// TypeScript source file directly.
//
// FP discipline: a name-only dictionary over-matches on its own (see exclusionReason below) —
// every hit goes through an exclusion pass before it's returned, and ambiguous names get "low"
// confidence rather than an assertion, so they're flagged for review, not treated as fact.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseColumns } from "../src/migration-sql-parse.js";

const RULES = [
  // --- HIPAA PHI identifiers / GDPR contact & identity PII ---
  [/(^|_)e?mail(_|$)/, "EMAIL", "PII", "high"],
  [/(^|_)(ssn|social_security)(_|$)/, "US_SSN", "SENSITIVE_PII", "high"],
  [/(date_of_birth|(^|_)dob(_|$)|birth_?date)/, "DOB", "PII", "high"],
  [/(^|_)(phone|mobile|telephone|cell)(_|$)/, "PHONE", "PII", "high"],
  [/(^|_)fax(_|$)/, "FAX", "PII", "high"],
  [/passport/, "PASSPORT", "SENSITIVE_PII", "high"],
  [/(driver_?licen[cs]e|license_number)/, "DRIVERS_LICENSE", "SENSITIVE_PII", "high"],
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
  [/(^|_)(address|street|city|zip|postal|postcode)(_|$)/, "ADDRESS", "PII", "medium"],
  [/(latitude|longitude|(^|_)geo|(^|_)lat(_|$)|(^|_)lng(_|$))/, "GEO", "PII", "low"],
  // --- GDPR Art. 9 special categories ---
  [/(political_(affiliation|party)|union_member(ship)?)/, "POLITICAL_OR_UNION", "SENSITIVE_PII", "high"],
  [/(genetic|dna_|genome)/, "GENETIC", "SENSITIVE_PII", "high"],
  [/(gender|ethnicit|(^|_)race(_|$)|religion|sexual)/, "SPECIAL_CATEGORY", "SENSITIVE_PII", "medium"],
  [/(^|_)(nationality|citizenship)(_|$)/, "NATIONALITY", "SENSITIVE_PII", "medium"],
  [/(health|diagnosis|medical|patient|prescription|(^|_)icd(_|$))/, "HEALTH", "PHI", "high"],
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

// Every rule above over-matches on real schemas (validated on ATC — see docs/audit-modules.md
// M10). These are the observed FP classes: a column *about* an infotype (a descriptor/category
// column, a boolean flag referencing the concept) is not a column *of* that infotype. Checked
// after a dictionary match, before the hit is returned — an excluded name never asserts PII.
const BOOLEAN_FLAG_NAME_PATTERN =
  /(^|_)(is|has|awaiting|needs|requires|pending)_|_(flag|reprompt|required|pending|enabled|requested|consent)(_|$)/;
const INFRA_HEALTH_PATTERN =
  /(^|_)(vendor|service|system|api|db|database|server|infra|upstream|integration|endpoint|app|deployment|pipeline|job|worker|queue)_?health(_|$)/;
// Suffix meaning "a category/type OF the concept," not the concept's value (e.g. email_category,
// address_type). Tradeoff: this would also swallow a genuine "blood_type" PHI column if one were
// ever added to the dictionary — none currently is, but flagging the tradeoff for future tuning.
const DESCRIPTOR_SUFFIX_PATTERN = /_(category|type|kind|class)$/;
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
  if (DESCRIPTOR_SUFFIX_PATTERN.test(column)) return "descriptor suffix — categorizes the concept, isn't the value";
  if (NAME_INFOTYPES.has(infotype) && tableName && ORG_ENTITY_TABLE_PATTERN.test(String(tableName).toLowerCase())) {
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

/**
 * @typedef {{infotype: string, category: "PII"|"SENSITIVE_PII"|"PHI"|"PCI"|"SECRET", confidence: "high"|"medium"|"low"}} ClassifyResult
 */

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
  const c = String(column).toLowerCase();
  for (const [pattern, infotype, category, confidence] of RULES) {
    if (!pattern.test(c)) continue;
    if (exclusionReason(c, sqlType, infotype, tableName)) return null;
    return { infotype, category, confidence };
  }
  if (tableName) {
    const t = String(tableName).toLowerCase();
    if (BARE_NUMBER_COLUMN_PATTERN.test(c) && PHONE_CONTEXT_TABLE_PATTERN.test(t)) {
      return { infotype: "PHONE", category: "PII", confidence: "medium" };
    }
    if (OPAQUE_STORE_COLUMN_PATTERN.test(c) && OPAQUE_STORE_TABLE_PATTERN.test(t)) {
      return { infotype: "OPAQUE_ENCRYPTED_STORE", category: "SECRET", confidence: "medium" };
    }
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
 * Stretch goal (issue #17): optional semantic fallback for names the dictionary can't resolve
 * deterministically — obfuscated/custom fields like `contact_handle`, `dob_estimate`. Not
 * implemented here: a real implementation would batch the *names only* (never values) of
 * unresolved columns to an LLM and expect the same ClassifyResult shape back, always at
 * confidence "low" (a semantic guess goes to review, never an assertion). Left as a documented
 * hook rather than a real call so this module doesn't pick up a new model-provider dependency;
 * see the PR body for the follow-up.
 * @typedef {(columns: {table_name: string, column_name: string}[]) => Promise<Map<string, ClassifyResult|null>>} SemanticClassifier
 * @param {{table_name: string, column_name: string, data_type?: string}[]} columns
 * @param {SemanticClassifier} [semanticClassifier]
 */
export async function classifyWithFallback(columns, semanticClassifier) {
  if (!semanticClassifier) return buildDataMap(columns);
  const unresolved = columns
    .filter((col) => !classifyColumn(col.column_name, col.data_type, col.table_name))
    .map((col) => ({ table_name: col.table_name, column_name: col.column_name }));
  if (unresolved.length === 0) return buildDataMap(columns);

  const semanticHits = await semanticClassifier(unresolved);
  return buildDataMap(columns, (col) => {
    const dictHit = classifyColumn(col.column_name, col.data_type, col.table_name);
    if (dictHit) return dictHit;
    const semanticHit = semanticHits.get(`${col.table_name}.${col.column_name}`);
    return semanticHit ? { ...semanticHit, source: "semantic" } : null;
  });
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

function report(cols) {
  const dataMap = buildDataMap(cols);
  const tables = Object.keys(dataMap);
  const hitCount = tables.reduce((n, t) => n + dataMap[t].columns.length, 0);
  const byCat = {};
  for (const t of tables) for (const c of dataMap[t].categories) byCat[c] = (byCat[c] || 0) + 1;

  console.log(`Scanned ${cols.length} columns. PII-bearing columns: ${hitCount} across ${tables.length} tables.`);
  console.log("Tables touching each category:", JSON.stringify(byCat));
  console.log("\nBy severity:");
  for (const t of tables.sort((a, b) => dataMap[b].severityScore - dataMap[a].severityScore)) {
    console.log(`  ${t} → ${dataMap[t].severity} (${dataMap[t].severityScore}): ${dataMap[t].infotypes.join(", ")}`);
  }
}

async function inventory() {
  const { default: postgres } = await import("postgres");
  const sql = postgres(process.env.SUPABASE_DB_URL, { max: 1, idle_timeout: 5 });
  const cols =
    await sql`SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position`;
  await sql.end();
  report(cols);
}

/**
 * Classifies every column declared in migration SQL text (`CREATE TABLE` statements) via
 * src/migration-sql-parse.ts's parseColumns, so M10 can run on source alone (#250) instead of
 * needing SUPABASE_DB_URL. Same under-extract-rather-than-mis-extract philosophy as that parser:
 * a formatting shape it doesn't recognize yields fewer columns, never a wrong one.
 * @param {string} sql concatenated migration SQL (one or more files)
 * @returns {{columns: {table_name: string, column_name: string, data_type?: string}[], dataMap: ReturnType<typeof buildDataMap>}}
 */
export function classifyMigrationSql(sql) {
  const columns = parseColumns(sql);
  return { columns, dataMap: buildDataMap(columns) };
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

function classifyFromSchema() {
  const target = process.argv[process.argv.indexOf("--schema") + 1];
  if (!target || !existsSync(target)) {
    console.error(`Usage: pii-classify --schema <path to a supabase/migrations dir or a single .sql file>${target ? ` — ${target} does not exist` : ""}`);
    process.exit(1);
  }
  const { columns } = classifyMigrationSql(readSchemaSql(target));
  if (columns.length === 0) {
    console.error(`No \`create table\` columns found via ${target} — check the path (expects supabase/migrations/*.sql shape).`);
    process.exit(1);
  }
  report(columns);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes("--selftest")) selftest();
  else if (process.argv.includes("--schema")) classifyFromSchema();
  else inventory();
}
