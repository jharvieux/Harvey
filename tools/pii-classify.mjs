// PII / PHI / PCI data-classification detector (audit module M10) — "detect, don't ask."
//
// Matches DB column NAMES + types (never values) against a dictionary aligned to standard
// taxonomies — Google Cloud DLP infoTypes, Microsoft Presidio entity types, GDPR Art. 9 special
// categories, HIPAA's 18 PHI identifiers, PCI-DSS cardholder/sensitive-auth data — so it's
// privacy-safe and only needs a read-only connection (or a static schema description with the
// same {table_name, column_name, data_type} shape as information_schema.columns).
//
//   node pii-classify.mjs --selftest
//   SUPABASE_DB_URL=... node pii-classify.mjs            # inventory a live DB (read-only)
//
// FP discipline: a name-only dictionary over-matches on its own (see exclusionReason below) —
// every hit goes through an exclusion pass before it's returned, and ambiguous names get "low"
// confidence rather than an assertion, so they're flagged for review, not treated as fact.

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
  [/(^|_)(device_id|imei|udid)(_|$)/, "DEVICE_ID", "SENSITIVE_PII", "medium"],
  [/(^|_)(vin|vehicle_identification)(_|$)/, "VEHICLE_ID", "PII", "medium"],
  [/(biometric|fingerprint|retina|iris_scan|face_?id|faceprint|voiceprint)/, "BIOMETRIC", "SENSITIVE_PII", "high"],
  // --- PCI-DSS cardholder / sensitive authentication data ---
  // CVV/CVC is "sensitive authentication data" — PCI-DSS forbids storing it post-authorization
  // at all, so a hit here is a compliance violation by itself (see INFOTYPE_POINT_OVERRIDES).
  [/(^|_)(cvv|cvc|card_verification|card_security_code)(_|$)/, "CVV", "PCI", "high"],
  [/(card_expir|card_exp_(month|year))/, "CARD_EXPIRY", "PCI", "medium"],
  [/(credit_?card|card_number|cc_num|(^|_)pan(_|$)|card_last4|card_brand)/, "CARD", "PCI", "high"],
  [/(^|_)(iban|account_number|routing|swift)(_|$)/, "BANK_ACCT", "PCI", "medium"],
  [/(stripe_customer|payment_method|payment_intent)/, "PAYMENT_REF", "PCI", "medium"],
  [/(wallet_address|crypto_address|btc_address|eth_address)/, "CRYPTO_WALLET", "SENSITIVE_PII", "medium"],
  [/(tax_id|(^|_)ein(_|$)|(^|_)vat(_|$)|(^|_)nino(_|$))/, "TAX_ID", "SENSITIVE_PII", "medium"],
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

function exclusionReason(column, sqlType) {
  if (sqlType && String(sqlType).toLowerCase() === "boolean") {
    return "sql type is boolean — PII/PHI/PCI values aren't booleans, this is a flag referencing the concept";
  }
  if (BOOLEAN_FLAG_NAME_PATTERN.test(column)) return "boolean-flag naming, not a data value";
  if (INFRA_HEALTH_PATTERN.test(column)) return "infra/system health-check naming, not medical health data";
  if (DESCRIPTOR_SUFFIX_PATTERN.test(column)) return "descriptor suffix — categorizes the concept, isn't the value";
  return null;
}

/**
 * @typedef {{infotype: string, category: "PII"|"SENSITIVE_PII"|"PHI"|"PCI", confidence: "high"|"medium"|"low"}} ClassifyResult
 */

/**
 * Classify a single column by name (and, optionally, its SQL type for the exclusion pass).
 * Never inspects data — name/type only. Returns null for no match or an excluded false positive.
 * @param {string} column
 * @param {string} [sqlType] e.g. information_schema.columns.data_type
 * @returns {ClassifyResult|null}
 */
export function classifyColumn(column, sqlType) {
  const c = String(column).toLowerCase();
  for (const [pattern, infotype, category, confidence] of RULES) {
    if (!pattern.test(c)) continue;
    if (exclusionReason(c, sqlType)) return null;
    return { infotype, category, confidence };
  }
  return null;
}

// Severity-weighting: lets a caller (an exposure finding in another module) weight severity by
// WHAT was exposed, not just THAT something was exposed. Category base points, scaled by match
// confidence, summed per distinct infotype on a table. CVV is overridden — PCI-DSS forbids
// storing it post-auth at all, so its presence alone should read Critical.
const CATEGORY_POINTS = { PII: 1, SENSITIVE_PII: 4, PHI: 6, PCI: 6 };
const CONFIDENCE_WEIGHT = { high: 1, medium: 0.6, low: 0.3 };
const INFOTYPE_POINT_OVERRIDES = { CVV: 12 };

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
export function buildDataMap(columns, resolve = (col) => classifyColumn(col.column_name, col.data_type)) {
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
    .filter((col) => !classifyColumn(col.column_name, col.data_type))
    .map((col) => ({ table_name: col.table_name, column_name: col.column_name }));
  if (unresolved.length === 0) return buildDataMap(columns);

  const semanticHits = await semanticClassifier(unresolved);
  return buildDataMap(columns, (col) => {
    const dictHit = classifyColumn(col.column_name, col.data_type);
    if (dictHit) return dictHit;
    const semanticHit = semanticHits.get(`${col.table_name}.${col.column_name}`);
    return semanticHit ? { ...semanticHit, source: "semantic" } : null;
  });
}

function selftest() {
  const cases = [
    ["email", "PII", "high"],
    ["customer_ssn", "SENSITIVE_PII", "high"],
    ["date_of_birth", "PII", "high"],
    ["card_last4", "PCI", "high"],
    ["cvv", "PCI", "high"],
    ["medical_record_number", "PHI", "high"],
    ["genetic_marker", "SENSITIVE_PII", "high"],
    ["product_name", "PII", "low"],
    ["created_at", null, null],
    ["tenant_id", null, null],
    // named FP cases (issue #17 acceptance)
    ["email_category", null, null],
    ["awaiting_dob_reprompt", null, null],
    ["vendor_health", null, null],
  ];
  let ok = 0;
  for (const [col, cat, conf] of cases) {
    const r = classifyColumn(col);
    const pass = cat === null ? r === null : r && r.category === cat && r.confidence === conf;
    console.log(`${pass ? "PASS" : "FAIL"}  ${col} → ${r ? r.category + "/" + r.confidence : "none"}`);
    if (pass) ok++;
  }
  console.log(`\n${ok}/${cases.length} passed`);
  process.exit(ok === cases.length ? 0 : 1);
}

async function inventory() {
  const { default: postgres } = await import("postgres");
  const sql = postgres(process.env.SUPABASE_DB_URL, { max: 1, idle_timeout: 5 });
  const cols =
    await sql`SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position`;
  await sql.end();

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

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes("--selftest")) selftest();
  else inventory();
}
