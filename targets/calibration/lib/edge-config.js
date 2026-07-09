// PLANTED BUG (P-SB-SECRET-KEY): a Supabase new-format secret key (sb_secret_...) hardcoded in
// source. The value is FAKE. The sb_secret_ prefix is Supabase's dedicated secret-key namespace
// (never public), so the custom gitleaks supabase-secret-key rule is high-precision → high.
const SUPABASE_SECRET_KEY = "sb_secret_Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi";

export function edgeConfigClient() {
  return { apiKey: SUPABASE_SECRET_KEY };
}
