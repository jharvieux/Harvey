import { createClient, type SupportedStorage } from "@supabase/supabase-js";

class CookieSessionStorage implements SupportedStorage {
  private readonly jar: Map<string, string>;
  readonly isServer = true;

  constructor(jar: Map<string, string>) {
    this.jar = jar;
  }

  getItem(key: string): string | null {
    return this.jar.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.jar.set(key, value);
  }

  removeItem(key: string): void {
    this.jar.delete(key);
  }
}

export function createServerClient(jar: Map<string, string>) {
  return createClient(process.env.SUPABASE_URL ?? "", process.env.SUPABASE_ANON_KEY ?? "", {
    auth: { storage: new CookieSessionStorage(jar), persistSession: true },
  });
}
