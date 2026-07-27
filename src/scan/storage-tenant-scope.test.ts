// #1198 — a Supabase storage path built from the caller-supplied filename alone, with no tenant
// prefix. The negative is the shipping condition: a path prefixed with a session-derived tenant id
// must stay silent, and it must not be confused with AUTH-upload-no-limit's unrelated defect.

import { describe, expect, it } from "vitest";
import { detectStorageTenantScopeFindings } from "./storage-tenant-scope.js";

const scan = (text: string, path = "src/lib/attachments.ts") => detectStorageTenantScopeFindings([{ path, text }]);

describe("storage-tenant-scope — fires on an unprefixed object path", () => {
  it("catches an upload keyed on the caller-supplied filename alone", () => {
    const out = scan(`
      export async function uploadAttachment(file: File, filename: string) {
        return supabase.storage.from("attachments").upload(filename, file);
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toContain("Storage object path without a tenant prefix");
    expect(out[0]!.precisionTier).toBe("review");
  });

  it("catches a download keyed on the caller-supplied filename alone", () => {
    const out = scan(`
      export async function downloadAttachment(filename: string) {
        return supabase.storage.from("attachments").download(filename);
      }
    `);
    expect(out).toHaveLength(1);
  });
});

describe("storage-tenant-scope — silent on the correct forms", () => {
  it("is silent when the path is prefixed with a session-derived tenant id", () => {
    expect(
      scan(`
        export async function uploadAttachment(file: File, filename: string) {
          const session = await auth();
          const path = \`\${session.user.tenantId}/\${filename}\`;
          return supabase.storage.from("attachments").upload(path, file);
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on a fixed string-literal path (not caller-supplied)", () => {
    expect(
      scan(`
        export async function uploadLogo(file: File) {
          return supabase.storage.from("public").upload("logo.png", file);
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on a .from(...) chain that isn't storage", () => {
    expect(
      scan(`
        export async function insertRow(filename: string) {
          return supabase.from("attachments").upload(filename);
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on non-shipping paths", () => {
    const text = `
      export async function uploadAttachment(file: File, filename: string) {
        return supabase.storage.from("attachments").upload(filename, file);
      }
    `;
    expect(scan(text, "src/lib/__tests__/attachments.ts")).toHaveLength(0);
  });
});
