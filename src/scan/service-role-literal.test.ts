import { describe, expect, it } from "vitest";
import { detectServiceRoleLiteralFindings } from "./service-role-literal.js";

// #664 — decode-based hardening of the #611 Gap A class. Real base64 JWT decode (not a
// base64-alignment signature), a decode-based demo-key exclusion, and cross-file const
// resolution. Each negative differs from the positive by exactly one gate.

const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const b64url = (obj: Record<string, unknown>) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const jwt = (payload: Record<string, unknown>) => `${header}.${b64url(payload)}.FAKEsig`;

const serviceRoleJwt = jwt({ iss: "supabase", ref: "test", role: "service_role" });
const anonJwt = jwt({ iss: "supabase", ref: "test", role: "anon" });
const demoJwt = jwt({ iss: "supabase-demo", role: "service_role" });

describe("service-role-literal (#664 — decoded-JWT service_role literal reaching createClient)", () => {
  it("flags a same-file literal decoding to role:service_role", () => {
    const text = `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(url, "${serviceRoleJwt}");
`;
    const findings = detectServiceRoleLiteralFindings([{ path: "src/lib/client.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Critical", precisionTier: "high" });
    expect(findings[0]?.evidence).toContain("service-role-literal");
  });

  it("flags a same-file const that const-propagates to createClient", () => {
    const text = `import { createClient } from "@supabase/supabase-js";
const KEY = "${serviceRoleJwt}";
export const admin = createClient(url, KEY);
`;
    expect(detectServiceRoleLiteralFindings([{ path: "src/lib/client.ts", text }])).toHaveLength(1);
  });

  it("flags a cross-file import: the literal is exported from another module", () => {
    const store = `export const SERVICE_KEY = "${serviceRoleJwt}";\n`;
    const client = `import { createClient } from "@supabase/supabase-js";
import { SERVICE_KEY } from "./keyStore";
export const admin = createClient(url, SERVICE_KEY);
`;
    const findings = detectServiceRoleLiteralFindings([
      { path: "src/lib/keyStore.ts", text: store },
      { path: "src/lib/client.ts", text: client },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toContain("src/lib/client.ts");
    expect(findings[0]?.evidence).toContain("keyStore.ts");
  });

  it("stays silent on an anon-role literal (public by design), same-file and cross-file", () => {
    const sameFile = `import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(url, "${anonJwt}");
`;
    expect(detectServiceRoleLiteralFindings([{ path: "src/lib/anon.ts", text: sameFile }])).toHaveLength(0);

    const store = `export const ANON_KEY = "${anonJwt}";\n`;
    const client = `import { createClient } from "@supabase/supabase-js";
import { ANON_KEY } from "./keyStore";
export const supabase = createClient(url, ANON_KEY);
`;
    expect(
      detectServiceRoleLiteralFindings([
        { path: "src/lib/keyStore.ts", text: store },
        { path: "src/lib/client.ts", text: client },
      ]),
    ).toHaveLength(0);
  });

  it("stays silent on the well-known supabase-demo local-dev key", () => {
    const text = `import { createClient } from "@supabase/supabase-js";
export const local = createClient("http://127.0.0.1:54321", "${demoJwt}");
`;
    expect(detectServiceRoleLiteralFindings([{ path: "src/lib/local.ts", text }])).toHaveLength(0);
  });

  it("stays silent on a process.env-sourced key (no literal to resolve)", () => {
    const text = `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
`;
    expect(detectServiceRoleLiteralFindings([{ path: "src/lib/admin.ts", text }])).toHaveLength(0);
  });

  it("stays silent on a malformed (non-3-segment) string that isn't a JWT", () => {
    const text = `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(url, "not-a-jwt-literal");
`;
    expect(detectServiceRoleLiteralFindings([{ path: "src/lib/admin.ts", text }])).toHaveLength(0);
  });
});
