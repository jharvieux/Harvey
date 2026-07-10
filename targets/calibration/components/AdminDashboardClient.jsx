"use client";

// Half of P-CLIENT-RENDER-AUTHZ (#136 — see app/admin/page.tsx): the ONLY authorization check in
// the whole flow is this client-side conditional. It hides the UI from a non-admin, but the
// `metrics` prop already carries the full admin dataset — it shipped inside the RSC payload the
// browser received before this component ever ran, and is readable from devtools/page source
// regardless of what isAdmin says.
export function AdminDashboardClient({ isAdmin, metrics }) {
  if (!isAdmin) return null;
  return <MetricsTable metrics={metrics} />;
}
