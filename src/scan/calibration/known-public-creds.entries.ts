// Known-public/test-credential recognizer (#225, generalizing #210 + #211). The Supabase
// local-dev demo key (#210) and a test/example SAML private key in a CI workflow (#211) are both
// gitleaks matches on an unambiguous secret shape, but neither is a live credential — see the
// internal correlation-marker rules in src/scan/rules/gitleaks-supabase.toml and the recognizer
// logic in src/scan/secrets.ts (parseGitleaksFindings). Positives proving the real, non-demo
// cases still fire live in secrets.entries.ts (P-SRV-ROLE-JWT-SRC) and b1 (P-PRIVATE-KEY).

import type { CorpusEntry } from "./types.js";

export const knownPublicCredsEntries: CorpusEntry[] = [
  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-SB-DEMO-KEY-SVC", kind: "negative", cls: "Supabase local-dev demo service_role key", location: "supabase/seed.sql", match: ["service_role"], note: "The fixed public demo key shipped by `supabase start` (decoded iss:\"supabase-demo\") committed in supabase/seed.sql. gitleaks still decodes and matches supabase-service-role-jwt, but the internal supabase-demo-key-marker rule co-locates (same file+line) and clears it entirely (#210) — the real, non-demo key at lib/admin.js (P-SRV-ROLE-JWT-SRC) is unaffected and still fires at high." },
  { id: "N-SB-DEMO-KEY-ANON", kind: "negative", cls: "Supabase local-dev demo anon key", location: "supabase/seed.sql", match: ["anon"], note: "The demo key's anon-role sibling, same file. Its role:anon claim never matched a high-precision rule to begin with; included to document the full published pair (#210)." },
  { id: "N-SB-DEMO-KEY-BEARER", kind: "negative", cls: "Supabase demo key used as a Bearer literal", location: "scripts/checks.mjs", note: "The demo service_role key inlined as a literal Authorization: Bearer token in a smoke-test script — models the \"anon-key equivalent\" FP class from #210 (harvey-http-authorization-bearer matches any 24+ char Bearer literal). Cleared by the same demo-key-marker correlation." },
  { id: "N-SAML-TEST-PRIVATE-KEY", kind: "negative", cls: "Test/example SAML private key in a CI workflow", location: ".github/workflows/saml-integration-test.yml", match: ["private-key"], note: "A base64 PEM private key committed inline in a CI workflow alongside test/example SAML IdP markers (ENTITY_ID, *.example.com) — a SAML integration-test keypair (e.g. SAML Jackson's fixtures), not a live credential (#211). gitleaks private-key still matches the decoded PEM block; the harvey-test-idp-marker correlation (same file) down-ranks it to review instead of clearing it outright — surfaced, never free-count. The genuine leaked key at certs/key.pem (P-PRIVATE-KEY) is unaffected and still fires at high." },
];
