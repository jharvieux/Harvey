// SYNTHETIC demonstration data for the public sample-report page.
// This is a fictional engagement ("Larkspur", an invented booking SaaS) written to show the
// SHAPE of a Harvey report. It is NOT a real client's data — real engagement findings live in
// report-template/findings.*.json and are never published here.

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Perf" | "Info";
export type LedgerStatus = "ran" | "part";

export const sampleMeta = {
  client: "Larkspur (sample)",
  subtitle: "Multi-tenant Supabase / Next.js booking app",
  tier: "Full audit",
  size: "Small · ~8k lines",
  verdict: "Not ready to scale",
  headline:
    "One cross-tenant read was proven live and one N+1 will not survive traffic. The rest are hardening, test-quality, and maintainability wins — all with named fixes.",
};

export const sampleCounts: { label: string; n: number; cls: string }[] = [
  { label: "Critical", n: 1, cls: "crit" },
  { label: "High", n: 1, cls: "crit" },
  { label: "Medium", n: 3, cls: "rev" },
  { label: "Low / Perf", n: 4, cls: "rev" },
  { label: "Clean", n: 1, cls: "pass" },
];

export const sampleFindings: {
  id: string;
  module: string;
  title: string;
  severity: Severity;
  location: string;
  evidence: string;
  impact: string;
  fix: string;
}[] = [
  {
    id: "F-01",
    module: "M2 · Live pen-test",
    title: "Cross-tenant read proven: user A can read user B's bookings",
    severity: "Critical",
    location: "public.bookings (RLS policy \"read own bookings\")",
    evidence:
      "On the stood-up stack, signed in as tenant A, a request to /rest/v1/bookings returned tenant B's rows. The policy uses USING (auth.role() = 'authenticated') — it checks that you're logged in, not that the row is yours.",
    impact:
      "Any signed-in customer can read every other customer's bookings, including names, dates, and contact details. This is a direct data-exposure incident, not a theoretical one.",
    fix: "Rewrite the policy to scope by owner: USING (user_id = auth.uid()). Re-run the cross-tenant matrix to confirm the boundary now holds.",
  },
  {
    id: "F-02",
    module: "M7 · Performance",
    title: "N+1 query on the dashboard loads one query per booking",
    severity: "High",
    location: "app/dashboard/page.tsx",
    evidence:
      "The dashboard fetches the booking list, then issues a separate customer lookup inside the render loop — N+1 queries that scale linearly with row count.",
    impact:
      "At 20 bookings the page is fine; at 2,000 it issues 2,000 queries per load and times out. This is what falls over on launch day.",
    fix: "Replace the per-row lookup with a single joined query (select with an embedded resource), or batch the customer IDs into one in() query.",
  },
  {
    id: "F-03",
    module: "M1 · Access control",
    title: "service_role key reachable from a client-imported module",
    severity: "Medium",
    location: "lib/supabase/admin.ts",
    evidence:
      "The admin client is instantiated with the service_role key in a module that is transitively imported by a client component. It is not currently called from the browser, but nothing prevents it.",
    impact:
      "The service_role key bypasses RLS entirely. A future accidental client import would bundle a master key to the database into the browser.",
    fix: "Move the admin client behind a server-only boundary and add import 'server-only' so an accidental client import fails the build.",
  },
  {
    id: "F-04",
    module: "M8 · Test quality",
    title: "The refund guard has a test that can't fail",
    severity: "Medium",
    location: "lib/billing/refund.ts",
    evidence:
      "Mutation testing: deleting the amount <= originalCharge check left every test green. No test asserts that an over-refund is rejected on money-critical logic.",
    impact:
      "A regression that allows refunding more than was charged would ship undetected — the suite would still pass.",
    fix: "Add one test asserting a refund greater than the original charge is rejected.",
  },
  {
    id: "F-05",
    module: "M10 · Data classification",
    title: "PII sitting in three columns with no access policy",
    severity: "Medium",
    location: "customers.phone, customers.address, customers.date_of_birth",
    evidence:
      "Schema classification flagged three PII columns on a table whose RLS is enabled but whose SELECT grant is broader than the policy intends.",
    impact:
      "Personal contact data is more broadly readable than the app appears to intend — a privacy and compliance exposure.",
    fix: "Tighten the SELECT grant to match the intended policy, and confirm no client path reads these columns unnecessarily.",
  },
  {
    id: "F-06",
    module: "M9 · App Router boundaries",
    title: "A Server Action mutates without checking the caller",
    severity: "Low",
    location: "app/bookings/actions.ts (cancelBooking)",
    evidence:
      "The Server Action accepts a bookingId and cancels it with no ownership check — it trusts that the UI only offers the button on the user's own bookings.",
    impact:
      "Anyone who can call the action with an arbitrary bookingId can cancel another tenant's booking (IDOR via a Server Action).",
    fix: "Verify the booking belongs to auth.uid() inside the action before mutating; never rely on the UI to enforce authorization.",
  },
  {
    id: "F-07",
    module: "M4 · Duplication",
    title: "Date-formatting logic copy-pasted across six components",
    severity: "Low",
    location: "components/** (6 clones)",
    evidence: "jscpd: the same timezone-handling block appears in six components, already diverged in two of them.",
    impact: "A fix to one copy silently misses the others — the two that diverged already render times differently.",
    fix: "Extract one formatBookingTime helper and replace the six copies.",
  },
  {
    id: "F-08",
    module: "M6 · Maintainability",
    title: "Hand-rolled session parsing where a library exists",
    severity: "Low",
    location: "lib/auth/session.ts",
    evidence:
      "Custom cookie parsing and JWT decoding reimplement what the Supabase auth-helpers already provide, with an edge case that mishandles an expired token.",
    impact: "Fragile reinvented auth code — the exact category that quietly breaks and is hard to reason about.",
    fix: "Replace with the maintained Supabase auth-helpers session handling.",
  },
  {
    id: "F-09",
    module: "M3 · Hotspots",
    title: "app/api/webhook/route.ts is the #1 hotspot",
    severity: "Info",
    location: "app/api/webhook/route.ts",
    evidence: "vitals: high complexity, 28 changes in 90 days, co-changes with 14 files.",
    impact: "Central, churny, and complex — a future-bug magnet with wide blast radius.",
    fix: "Decompose into handlers. High value but slow and risky — schedule as a planned refactor, not a quick win.",
  },
  {
    id: "F-10",
    module: "M5 · Dead code",
    title: "No dead code worth pruning",
    severity: "Info",
    location: "repo-wide",
    evidence: "knip found 3 unused exports, all framework entry points — nothing to remove.",
    impact: "Clean. Noted for transparency; not every module produces a finding.",
    fix: "No action.",
  },
];

export const sampleLedger: { module: string; why: string; status: LedgerStatus }[] = [
  { module: "M1 · Access control & data security", why: "RLS + auth reviewed, live-verified", status: "ran" },
  { module: "M2 · Live pen-test", why: "stack stood up, cross-tenant matrix run", status: "ran" },
  { module: "M3 · Hotspot analysis", why: "churn × complexity computed", status: "ran" },
  { module: "M4 · Duplication", why: "jscpd + near-miss pass", status: "ran" },
  { module: "M5 · Dead code", why: "knip over installed deps", status: "ran" },
  { module: "M6 · Maintainability", why: "indicators + reviewed verdict", status: "ran" },
  { module: "M7 · Performance", why: "code tier + DB advisors + Lighthouse", status: "ran" },
  { module: "M8 · Test quality", why: "mutation run complete", status: "ran" },
  { module: "M9 · App Router boundaries", why: "static AST pass", status: "ran" },
  { module: "M10 · Data classification", why: "schema classification; live PII grants pending client sign-off", status: "part" },
];
