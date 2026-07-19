import { createClient } from "@supabase/supabase-js";

// PLANTED BUG (P-SRV-ROLE-LITERAL-CLIENT, #611 Gap A): a Vite/no-code SPA hardcodes the Supabase
// service_role key as a JWT LITERAL (the .env carries a VITE_ var, but the client module inlines a
// literal) and passes it — via a service-role-named const — to createClient. Semgrep constant-
// propagation resolves the identifier to the literal, so harvey-service-role-literal fires on the
// createClient call. Full RLS bypass shipped to every visitor. Token is FAKE (fake signature).
const SUPABASE_SERVICE_ROLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpeHR1cmVyZWYwMSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.FAKEsig_notreal_000000000000000000000";
export const admin = createClient(import.meta.env.VITE_SUPABASE_URL, SUPABASE_SERVICE_ROLE);
