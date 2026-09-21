import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const boundary = vi.hoisted(() => ({
  jar: new Map<string, string>(),
  getUser: vi.fn<(token: string) => Promise<{ data: { user: { id: string } | null }; error: unknown }>>(),
  createClient: vi.fn(),
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({ get: (name: string) => {
    const value = boundary.jar.get(name);
    return value === undefined ? undefined : { value };
  } }),
}));
vi.mock("@supabase/supabase-js", () => ({
  createClient: (...args: unknown[]) => boundary.createClient(...args),
}));

import {
  checkPassword, isAuthenticated, resolveSupabaseUserId, resolveUserId, sessionCookie,
  type SupabaseAuthLike,
} from "../lib/auth.js";
import { POST as login } from "../app/api/login/route.js";

beforeEach(() => {
  boundary.jar.clear();
  boundary.getUser.mockReset();
  boundary.createClient.mockReset().mockReturnValue({ auth: { getUser: boundary.getUser } });
  vi.stubEnv("EPIC_BUILDER_PASSWORD", "correct horse battery staple");
  vi.stubEnv("EPIC_BUILDER_SESSION_SECRET", "separate signing secret");
  vi.stubEnv("EPIC_BUILDER_AUTH", "");
  vi.stubEnv("SUPABASE_URL", "https://fixture.invalid");
  vi.stubEnv("SUPABASE_ANON_KEY", "fixture-anon-key");
  vi.stubEnv("SUPABASE_AUTH_COOKIE", undefined);
});
afterEach(() => vi.unstubAllEnvs());

describe("shared-password and signed-cookie boundary", () => {
  it("accepts only the configured password, including unequal-length rejection and absent credentials", () => {
    expect(checkPassword("correct horse battery staple")).toBe(true);
    expect(checkPassword("correct horse battery staplf")).toBe(false);
    expect(checkPassword("short")).toBe(false);
    expect(checkPassword("")).toBe(false);
    vi.stubEnv("EPIC_BUILDER_PASSWORD", "");
    expect(checkPassword("correct horse battery staple")).toBe(false);
    expect(checkPassword("")).toBe(false);
    vi.stubEnv("EPIC_BUILDER_PASSWORD", undefined);
    expect(process.env.EPIC_BUILDER_PASSWORD).toBeUndefined();
    expect(checkPassword("dev-password")).toBe(false);
  });

  it("mints with production code and resolves only its intact signed value", async () => {
    const cookie = sessionCookie();
    expect(cookie.name).toBe("epic_session");
    expect(cookie.options).toEqual({
      httpOnly: true, sameSite: "strict", secure: true, path: "/", maxAge: 43_200,
    });
    expect(await resolveUserId()).toBeNull();
    expect(await isAuthenticated()).toBe(false);
    boundary.jar.set(cookie.name, cookie.value);
    expect(await resolveUserId()).toBe("operator");
    expect(await isAuthenticated()).toBe(true);
    const [value, mac] = cookie.value.split(".");
    boundary.jar.set(cookie.name, value + "X." + mac);
    expect(await resolveUserId()).toBeNull();
    boundary.jar.set(cookie.name, value + "." + "0".repeat(mac!.length));
    expect(await resolveUserId()).toBeNull();
    boundary.jar.set(cookie.name, value + "." + mac!.slice(0, -1));
    expect(await resolveUserId()).toBeNull();
    boundary.jar.set(cookie.name, value + ".not-hex");
    expect(await resolveUserId()).toBeNull();
    boundary.jar.set(cookie.name, value + "." + mac + ".extra");
    expect(await resolveUserId()).toBeNull();
    boundary.jar.delete(cookie.name);
    expect(await resolveUserId()).toBeNull();
  });

  it("denies absent signing configuration and a cookie signed with a different key", async () => {
    const cookie = sessionCookie();
    boundary.jar.set(cookie.name, cookie.value);
    vi.stubEnv("EPIC_BUILDER_SESSION_SECRET", "another signing secret");
    expect(await resolveUserId()).toBeNull();
    vi.stubEnv("EPIC_BUILDER_SESSION_SECRET", "");
    expect(await resolveUserId()).toBeNull();
    expect(() => sessionCookie()).toThrow("EPIC_BUILDER_SESSION_SECRET is required");
    vi.stubEnv("EPIC_BUILDER_SESSION_SECRET", undefined);
    expect(process.env.EPIC_BUILDER_SESSION_SECRET).toBeUndefined();
    expect(await resolveUserId()).toBeNull();
    expect(() => sessionCookie()).toThrow("EPIC_BUILDER_SESSION_SECRET is required");
  });

  it("makes the real login handler reject bad input and set a protected cookie on success", async () => {
    const request = (body: string) => new Request("http://localhost/api/login", {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    const denied = await login(request(JSON.stringify({ password: "wrong" })));
    expect(denied.status).toBe(401);
    expect(denied.headers.get("set-cookie")).toBeNull();
    const absent = await login(request("{}"));
    expect(absent.status).toBe(401);
    expect(absent.headers.get("set-cookie")).toBeNull();
    const accepted = await login(request(JSON.stringify({ password: "correct horse battery staple" })));
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({ ok: true });
    const header = accepted.headers.get("set-cookie") ?? "";
    expect(header).toContain("epic_session=");
    expect(header).toContain("HttpOnly");
    expect(header).toContain("Secure");
    expect(header).toContain("SameSite=strict");
    expect(header).toContain("Max-Age=43200");
    const malformed = await login(request("{"));
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get("set-cookie")).toBeNull();
  });
});

describe("provider-backed request identity", () => {
  it("selects the configured cookie and verified user partition only in Supabase mode", async () => {
    const shared = sessionCookie();
    boundary.jar.set(shared.name, shared.value);
    expect(await resolveUserId()).toBe("operator");
    expect(boundary.createClient).not.toHaveBeenCalled();
    vi.stubEnv("EPIC_BUILDER_AUTH", "supabase");
    vi.stubEnv("SUPABASE_AUTH_COOKIE", "custom-access-token");
    expect(await resolveUserId()).toBeNull();
    expect(boundary.createClient).not.toHaveBeenCalled();
    boundary.jar.set("custom-access-token", "verified-token");
    boundary.getUser.mockResolvedValue({ data: { user: { id: "user-b" } }, error: null });
    expect(await resolveUserId()).toBe("user-b");
    expect(boundary.getUser).toHaveBeenCalledExactlyOnceWith("verified-token");
    expect(boundary.createClient).toHaveBeenCalledWith(
      "https://fixture.invalid", "fixture-anon-key", { auth: { persistSession: false } },
    );
  });

  it("denies rejected, missing and throwing provider identities", async () => {
    vi.stubEnv("EPIC_BUILDER_AUTH", "supabase");
    expect(process.env.SUPABASE_AUTH_COOKIE).toBeUndefined();
    boundary.jar.set("sb-access-token", "rejected-token");
    boundary.getUser.mockResolvedValueOnce({ data: { user: { id: "unverified" } }, error: { message: "rejected" } });
    expect(await resolveUserId()).toBeNull();
    expect(boundary.getUser).toHaveBeenNthCalledWith(1, "rejected-token");
    boundary.jar.set("sb-access-token", "missing-user-token");
    boundary.getUser.mockResolvedValueOnce({ data: { user: null }, error: null });
    expect(await resolveUserId()).toBeNull();
    expect(boundary.getUser).toHaveBeenNthCalledWith(2, "missing-user-token");
    boundary.jar.set("sb-access-token", "throwing-token");
    boundary.getUser.mockRejectedValueOnce(new Error("provider unavailable"));
    expect(await resolveUserId()).toBeNull();
    expect(boundary.getUser).toHaveBeenNthCalledWith(3, "throwing-token");
    boundary.jar.delete("sb-access-token");
    expect(await resolveUserId()).toBeNull();
    expect(boundary.getUser).toHaveBeenCalledTimes(3);
    expect(boundary.createClient).toHaveBeenCalledTimes(3);
  });

  it("denies a direct provider error without yielding an unverified id", async () => {
    const client: SupabaseAuthLike = { auth: { getUser: async () => ({
      data: { user: { id: "unverified" } }, error: { message: "invalid" },
    }) } };
    expect(await resolveSupabaseUserId("bad", client)).toBeNull();
    expect(await resolveSupabaseUserId(undefined, client)).toBeNull();
  });
});
