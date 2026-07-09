// Proves the Supabase auth path (issue #103) resolves a verified access token to a user id — the storage
// partition key (design §4, §6) — with @supabase/supabase-js MOCKED. No cookies, no live Supabase: the
// pure resolveSupabaseUserId is exercised directly with a fake auth client.

import { describe, expect, it } from "vitest";
import { resolveSupabaseUserId, type SupabaseAuthLike } from "../lib/auth.js";

function fakeAuth(valid: Record<string, string>): SupabaseAuthLike {
  return {
    auth: {
      getUser: (jwt: string) =>
        Promise.resolve(
          valid[jwt]
            ? { data: { user: { id: valid[jwt]! } }, error: null }
            : { data: { user: null }, error: { message: "invalid token" } },
        ),
    },
  };
}

describe("supabase auth", () => {
  const client = fakeAuth({ "good-token": "c0ffee00-0000-4000-8000-000000000000" });

  it("resolves a valid access token to its user id", async () => {
    expect(await resolveSupabaseUserId("good-token", client)).toBe("c0ffee00-0000-4000-8000-000000000000");
  });

  it("returns null for a missing or invalid token", async () => {
    expect(await resolveSupabaseUserId(undefined, client)).toBeNull();
    expect(await resolveSupabaseUserId("forged", client)).toBeNull();
  });
});
