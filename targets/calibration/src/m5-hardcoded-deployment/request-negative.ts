import { env } from "../lib/env";

export async function reconcileLedger(path: string) {
  return fetch(new URL(path, env.LEDGER_BASE_URL), { method: "POST" });
}
