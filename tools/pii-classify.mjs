// PII / data-classification detector (audit) — "detect, don't ask."
//
// Matches DB column NAMES + types against a standard PII dictionary (Google Cloud
// DLP infoTypes / Microsoft Presidio / GDPR special categories / PHI / PCI) — names
// only, never values, so no real PII is touched and only a read-only connection is
// needed. Output feeds the app-context profile and auto-weights exposure severity.
//
//   node pii-classify.mjs --selftest
//   SUPABASE_DB_URL=... node pii-classify.mjs            # inventory a live DB (read-only)
//
// Dictionary is name-based → FP-aware: ambiguous names (e.g. "name") get low
// confidence (could be a product/display name), flagged for review not assertion.

const RULES = [
  [/(^|_)e?mail(_|$)/, "EMAIL", "PII", "high"],
  [/(^|_)(ssn|social_security)(_|$)/, "US_SSN", "SENSITIVE_PII", "high"],
  [/(date_of_birth|(^|_)dob(_|$)|birth_?date)/, "DOB", "PII", "high"],
  [/(^|_)(phone|mobile|telephone|cell)(_|$)/, "PHONE", "PII", "high"],
  [/passport/, "PASSPORT", "SENSITIVE_PII", "high"],
  [/(driver_?licen[cs]e|license_number)/, "DRIVERS_LICENSE", "SENSITIVE_PII", "high"],
  [/(credit_?card|card_number|cc_num|(^|_)pan(_|$)|card_last4|card_brand)/, "CARD", "PCI", "high"],
  [/(^|_)(iban|account_number|routing|swift)(_|$)/, "BANK_ACCT", "PCI", "medium"],
  [/(stripe_customer|payment_method|payment_intent)/, "PAYMENT_REF", "PCI", "medium"],
  [/(tax_id|(^|_)ein(_|$)|(^|_)vat(_|$)|(^|_)nino(_|$))/, "TAX_ID", "SENSITIVE_PII", "medium"],
  [/(^|_)(ip|ip_address)(_|$)/, "IP", "PII", "medium"],
  [/(first_name|last_name|full_name|surname|given_name|middle_name)/, "NAME", "PII", "medium"],
  [/(^|_)(address|street|city|zip|postal|postcode)(_|$)/, "ADDRESS", "PII", "medium"],
  [/(gender|ethnicit|(^|_)race(_|$)|religion|sexual)/, "SPECIAL_CATEGORY", "SENSITIVE_PII", "medium"],
  [/(health|diagnosis|medical|patient|prescription|(^|_)icd(_|$))/, "HEALTH", "PHI", "high"],
  [/(latitude|longitude|(^|_)geo|(^|_)lat(_|$)|(^|_)lng(_|$))/, "GEO", "PII", "low"],
  [/(^|_)name(_|$)/, "NAME?", "PII", "low"], // ambiguous: product/display name — review
];

export function classifyColumn(column) {
  const c = String(column).toLowerCase();
  for (const [re, infotype, category, confidence] of RULES) {
    if (re.test(c)) return { infotype, category, confidence };
  }
  return null;
}

function selftest() {
  const cases = [
    ["email", "PII", "high"], ["customer_ssn", "SENSITIVE_PII", "high"],
    ["date_of_birth", "PII", "high"], ["card_last4", "PCI", "high"],
    ["product_name", "PII", "low"], ["created_at", null, null], ["tenant_id", null, null],
  ];
  let ok = 0;
  for (const [col, cat, conf] of cases) {
    const r = classifyColumn(col);
    const pass = (cat === null ? r === null : r && r.category === cat && r.confidence === conf);
    console.log(`${pass ? "PASS" : "FAIL"}  ${col} → ${r ? r.category + "/" + r.confidence : "none"}`);
    if (pass) ok++;
  }
  console.log(`\n${ok}/${cases.length} passed`);
  process.exit(ok === cases.length ? 0 : 1);
}

async function inventory() {
  const { default: postgres } = await import("postgres");
  const sql = postgres(process.env.SUPABASE_DB_URL, { max: 1, idle_timeout: 5 });
  const cols = await sql`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position`;
  await sql.end();
  const hits = cols.map((c) => ({ ...c, ...classifyColumn(c.column_name) })).filter((c) => c.category);
  const byCat = {};
  for (const h of hits) byCat[h.category] = (byCat[h.category] || 0) + 1;
  const tables = new Set(hits.map((h) => h.table_name));
  console.log(`Scanned ${cols.length} columns. PII-bearing columns: ${hits.length} across ${tables.size} tables.`);
  console.log("By category:", JSON.stringify(byCat));
  console.log("\nHigh-confidence sample:");
  for (const h of hits.filter((x) => x.confidence === "high").slice(0, 18)) console.log(`  ${h.table_name}.${h.column_name} → ${h.infotype} (${h.category})`);
  console.log("\nLow-confidence (review):", hits.filter((x) => x.confidence === "low").length);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes("--selftest")) selftest();
  else inventory();
}
