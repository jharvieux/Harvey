// Part of P-SRV-ROLE-LITERAL-CROSSFILE (#664 Gap C): the service_role JWT literal lives in ITS
// OWN module, exported as a named const, and is imported by crossFileServiceClient.ts rather
// than being inlined at the createClient call site. Token is FAKE (fake signature).
export const SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpeHR1cmVyZWYwMiIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.FAKEsig_notreal_000000000000000000002";
