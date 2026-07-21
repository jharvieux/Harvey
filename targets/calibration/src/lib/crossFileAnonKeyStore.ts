// Part of N-SRV-ROLE-CROSSFILE-ANON (#664 Gap C): the SAME cross-file shape as
// serviceRoleKeyStore.ts, but the exported literal is the anon key (role:anon) — public by
// design. Regression guard that cross-file resolution still discriminates on the decoded role
// claim, not merely on "an imported literal reached createClient".
export const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpeHR1cmVyZWYwMiIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.FAKEsig_notreal_000000000000000000003";
