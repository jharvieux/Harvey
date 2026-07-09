// Batch B8 (#71) — Supabase connected-tier config (spec `docs/design/spec-71-security-corpus.md`
// §"Batch 10 — Supabase project config"). Every entry here is `expectedTier: "connected"`: it
// needs a live Supabase project (`get_advisors`, Management API config, `list_extensions`) to
// confirm, so buildCoverageMatrix always scores it N/A, never a pass/fail — these can't regress
// the static free-count gate (src/scan/calibration.ts). No `module` field: these are M1/connected
// entries, not a separate cross-module tool.
//
// Detection code for all seven advisor lints already exists and is generic — parseAdvisorFindings
// (src/scan/supabase-advisors.ts) maps ANY lint name through CURATED_SEVERITY, which already
// carries rls_disabled_in_public, rls_enabled_no_policy, auth_users_exposed, security_definer_view,
// function_search_path_mutable, rls_references_user_metadata, and sensitive_columns_exposed — so
// this batch adds fixtures + calibration rows + recorded-JSON parsing tests (supabase-advisors.
// test.ts), not new detection code. Storage/auth-config/extension checks (checkPublicBuckets
// WithNoPolicies, checkAuthConfig, checkDangerousExtensions in supabase-config.ts) were already
// wired for a prior batch and are reused unchanged here. Fixtures live in
// targets/calibration/supabase/migrations/20260709000004_b8_connected_advisors.sql and
// targets/calibration/supabase/config.toml. See GROUND-TRUTH.md §"Batch B8" — live advisor
// confirmation against a running project is a deferred main-session pass (this PR is offline-only:
// parsing-logic unit tests + the static gate no-regression check).

import type { CorpusEntry } from "./types.js";

export const b8SupaEntries: CorpusEntry[] = [
  // --- POSITIVES (connected tier — N/A on a static run, never a free-count claim) ---
  { id: "P-RLS-ENABLED-NO-POLICY", kind: "positive", cls: "RLS enabled, zero policies (tenant-facing table)", location: "reports", expectedTier: "connected", note: "public.reports (migrations/20260709000004) gets RLS enabled but no policy is ever created — unlike service_state (N-RLS-DENY-ALL), reports is meant to be tenant-readable, so this is a genuine 'forgot to finish RLS' signal. Splinter rls_enabled_no_policy, curated to Medium in CURATED_SEVERITY." },
  { id: "P-AUTH-USERS-EXPOSED", kind: "positive", cls: "auth.users exposed via a public view", location: "user_directory", expectedTier: "connected", note: "public.user_directory selects id/email/created_at from auth.users and grants select to anon/authenticated. Splinter auth_users_exposed, curated to Critical." },
  { id: "P-SECDEF-VIEW", kind: "positive", cls: "SECURITY DEFINER view", location: "tenant_totals", expectedTier: "connected", note: "public.tenant_totals aggregates invoices with no security_invoker=true option, so it runs as the owning role and bypasses the invoices RLS policies for whoever reads it. Splinter security_definer_view, curated to High." },
  { id: "P-FN-SEARCH-PATH", kind: "positive", cls: "Mutable search_path on a function", location: "get_invoice_total", expectedTier: "connected", note: "public.get_invoice_total has no `set search_path`, unlike public.current_tenant_id() (the N-DEFINER-SCOPED negative, which sets it). Splinter function_search_path_mutable, curated to Medium." },
  { id: "P-RLS-USER-META", kind: "positive", cls: "RLS policy trusts user_metadata", location: "internal_notes", expectedTier: "connected", note: "internal_notes_admin_read policy checks (auth.jwt() -> 'user_metadata' ->> 'is_admin') — a claim any authenticated user can set on themselves via the client SDK. Splinter rls_references_user_metadata, curated to High." },
  { id: "P-SENSITIVE-COLS", kind: "positive", cls: "Sensitive column exposed via API", location: "support_tickets", match: ["ssn"], expectedTier: "connected", note: "support_tickets.customer_ssn is a known-sensitive column name pattern reachable via PostgREST for any tenant member — the column itself, not the row set, is the exposure. Splinter sensitive_columns_exposed, curated to High." },
  { id: "P-STORAGE-PUBLIC", kind: "positive", cls: "Public storage bucket, zero object policies", location: "avatars", expectedTier: "connected", note: "[storage.buckets.avatars] public=true in config.toml; no storage.objects policy scoped to it anywhere in supabase/migrations/. checkPublicBucketsWithNoPolicies (supabase-config.ts), already wired — high-precision once run against the live bucket/policy query." },
  { id: "P-LEAKED-PW-OFF", kind: "positive", cls: "Leaked-password (HIBP) protection disabled", location: "Auth config", match: ["hibp", "leaked-password"], expectedTier: "connected", note: "Not representable in supabase/config.toml — HIBP protection is a hosted-project Auth setting with no local CLI field, so this positive has no local fixture; it's confirmed only via a live GET /v1/projects/{ref}/config/auth read. checkAuthConfig(password_hibp_enabled: false) is already wired and unit-tested against a recorded response (supabase-config.test.ts)." },
  { id: "P-EMAIL-CONFIRM-OFF", kind: "positive", cls: "Email confirmation disabled", location: "config.toml", match: ["enable_confirmations", "email confirmation"], expectedTier: "connected", note: "[auth.email] enable_confirmations = false in config.toml — the local-CLI equivalent of the hosted mailer_autoconfirm=true Auth setting checkAuthConfig flags. Confirmed live via the Management API config read, not by parsing config.toml directly." },
  { id: "P-OTP-LONG-EXPIRY", kind: "positive", cls: "OTP expiry far past baseline", location: "config.toml", match: ["otp_expiry", "otp expiry"], expectedTier: "connected", note: "[auth.email] otp_expiry = 86400 (24h) in config.toml, vs. checkAuthConfig's 3600s (1h) baseline. Confirmed live via the Management API config read." },
  { id: "P-OAUTH-REDIRECT-WILD", kind: "positive", cls: "Wildcard OAuth/redirect allowlist", location: "config.toml", match: ["redirect_urls", "redirect allowlist", "wildcard"], expectedTier: "connected", note: "[auth] additional_redirect_urls includes a bare \"*\" in config.toml. checkAuthConfig(uri_allow_list.includes('*')) is already wired and unit-tested; confirmed live via the Management API config read." },
  { id: "P-PGNET-SSRF", kind: "positive", cls: "Dangerous extension (pg_net) with a callable RPC", location: "fetch_webhook_preview", match: ["pg_net", "net.http_get"], expectedTier: "connected", note: "pg_net is enabled and public.fetch_webhook_preview (SECURITY DEFINER) calls net.http_get(p_url) with a caller-supplied URL, granted to authenticated — a DB-originated SSRF primitive, not just a dormant extension. checkDangerousExtensions (supabase-config.ts) flags the extension; already wired." },

  // --- NEGATIVES (connected tier — must NOT be flagged when live-confirmed) ---
  { id: "N-DEFINER-SCOPED", kind: "negative", cls: "SECURITY DEFINER function with search_path set + auth.uid() check", location: "current_tenant_id", expectedTier: "connected", note: "public.current_tenant_id() (schema migration) is SECURITY DEFINER but sets search_path = public and scopes its query by auth.uid() — the correct pattern. Splinter function_search_path_mutable does not fire; contrasts P-FN-SEARCH-PATH." },
  { id: "N-STORAGE-PRIVATE", kind: "negative", cls: "Private storage bucket", location: "invoices-private", expectedTier: "connected", note: "[storage.buckets.invoices-private] public=false in config.toml. checkPublicBucketsWithNoPolicies filters on public=true first — cleared regardless of policy count; contrasts P-STORAGE-PUBLIC." },
];
