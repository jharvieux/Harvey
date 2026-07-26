// Reproducible builder for `gitleaks-8.30.1-corpus.json` (#1156, #1150 row 9). Writes a
// planted-secret corpus to a throwaway temp dir — one scenario per `parseGitleaksFindings` branch —
// then runs the SAME pinned invocation `runGitleaks` uses (custom config + default ruleset,
// --no-git --max-decode-depth 2) and prints the real report to stdout. The committed fixture is this
// output with unrelated records dropped (see PROVENANCE.md); field VALUES are never hand-edited.
// Re-capture:  node src/scan/__fixtures__/gitleaks/build-corpus.mjs > /tmp/gl.json
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath, URL } from "node:url";
import { join } from "node:path";

// A structural (fake, non-functional) Supabase JWT whose DECODED payload carries the given claims.
// gitleaks --max-decode-depth 2 base64-decodes the body, so the custom rules match the decoded
// "role"/"iss" claims and map the match back to the source line — exactly how the real demo key
// makes supabase-service-role-jwt and supabase-demo-key-marker co-locate (#210).
const jwt = (payload) => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.c2ln`;
};
const SERVICE_JWT = jwt({ iss: "supabase", role: "service_role" });
const DEMO_SERVICE_JWT = jwt({ iss: "supabase-demo", role: "service_role" });

const FILES = {
  // A real (non-demo) service-role JWT — supabase-service-role-jwt, high/Critical, no demo marker.
  "lib/admin.ts": `export const admin = "${SERVICE_JWT}";\n`,
  // The local-dev demo service-role key: its decoded body carries BOTH role:service_role and
  // iss:supabase-demo, so both rules fire on the same line → cleared by co-location (#210).
  "supabase/seed.sql": `insert into secrets values ('${DEMO_SERVICE_JWT}');\n`,
  // A private key with no test-IdP context — private-key, high.
  "certs/key.pem": "-----BEGIN PRIVATE KEY-----\nMIIFAKEfake0000000000000000000000000000000000000000000000000000\n-----END PRIVATE KEY-----\n",
  // A private key sharing a NON-workflow file with a test-IdP marker — stays high (#211 negative).
  "certs/idp-key.pem": "ENTITY_ID=urn:test\n-----BEGIN PRIVATE KEY-----\nMIIFAKEfake1111111111111111111111111111111111111111111111111111\n-----END PRIVATE KEY-----\n",
  // A private key + test-IdP marker inside a CI workflow — private-key down-ranked to review (#211).
  ".github/workflows/saml-test.yml":
    "env:\n  ENTITY_ID: urn:test:idp\n  KEY: |\n    -----BEGIN PRIVATE KEY-----\n    MIIFAKEfake2222222222222222222222222222222222222222222222222222\n    -----END PRIVATE KEY-----\n",
  // A generic keyword+value match — generic-api-key, review tier.
  "lib/config.ts": 'export const OPENAI_API_KEY = "Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2";\n',
  // A Stripe secret token — stripe-access-token, exercises value redaction (#308).
  "lib/pay.ts": 'export const key = "sk_test_51Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj";\n',
  // A DB URI with an inline password — harvey-db-uri-credentials, exercises password redaction (#308).
  "supabase/migrations/001.sql": "-- postgres://appuser:S3cr3tP4ssZ9Qm2vXc@db.example.supabase.co/app\n",
};

const dir = mkdtempSync(join(tmpdir(), "harvey-gitleaks-corpus-"));
for (const [rel, content] of Object.entries(FILES)) {
  const full = join(dir, rel);
  mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
  writeFileSync(full, content);
}

const config = fileURLToPath(new URL("../../rules/gitleaks-supabase.toml", import.meta.url));
const report = join(dir, "report.json");
execFileSync(
  "gitleaks",
  ["detect", "--no-git", "-s", dir, "--config", config, "--max-decode-depth", "2", "--report-format", "json", "--report-path", report, "--exit-code", "0"],
  { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 },
);
process.stdout.write(readFileSync(report, "utf8"));
rmSync(dir, { recursive: true, force: true });
