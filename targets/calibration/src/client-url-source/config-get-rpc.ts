// #1708 NEGATIVE (N-CLIENT-URL-CONFIG-GET). A boot-time configuration registry read at module
// scope and handed to a raw-SQL-executor RPC. There is no request, no DOM and no URL anywhere in
// this module. It is here because injection.yml's client-URL-param source (x-client-url-source)
// once carried a receiver-agnostic `$SP.get(...)`, which fires on any `.get()` at all — the exact
// shape base.yml's canonical request block records as the reason IT carries no bare `$SP.get(...)`.
// harvey-sql-injection-rpc is ERROR/HIGH, i.e. the GRADED free count, so this pairing is the one
// that reaches a client's letter grade. A finding here means the receiver binding came off.
declare const appConfig: Map<string, string>;
declare const serviceClient: { rpc(fn: string, args: Record<string, unknown>): Promise<unknown> };

export async function runNightlyRollup() {
  const rollupView = appConfig.get("nightlyRollupView");
  return serviceClient.rpc("exec_sql", { query: `select * from ${rollupView}` });
}
