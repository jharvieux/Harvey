// #1297 — the standing invariant: Harvey never places a secret in a child process's argv.
//
// Why argv specifically. MEASURED 2026-07-28 on darwin 25.5.0 as an unprivileged user:
//   ps -o command= -p <other-uid-pid>   -> prints the full argv of a process owned by root
//   ps -Eo command= -p <other-uid-pid>  -> prints the SAME string; no environment is appended
// So argv is readable by every local user for the child's lifetime, while the environment is
// readable only by the same uid (darwin: `ps -E` on one's own processes; Linux: /proc/<pid>/environ,
// mode 0400 owner-only). Moving a secret argv -> env does not make it unreadable; it narrows the
// audience from "any local account" to "the account already running the scan". That is the residual
// surface, and it is the one Harvey's own process already has.
//
// Harvey is a security audit running on a client's machine, so a scan must not widen the attack
// surface of the app it is auditing. The helpers here are the sanctioned ways to hand a secret to a
// child: the child's environment, or its stdin.
//
// SCOPE — this invariant covers ARGV ONLY, deliberately (criterion 6 of #1413). "On disk" and "in a
// log" are real secret surfaces but a different class: argv is world-readable by every local account
// for the child's lifetime with no action required, whereas Harvey's disk writes go to operator-owned
// temp dirs and its report output is already redaction-gated. Those two surfaces are not covered by
// the argv rail below and are NOT claimed to be; extending the same structural treatment to them is
// tracked as the #1413 remainder. Recording the boundary here so a reader does not mistake an
// argv-clean run for a whole-secret-lifecycle guarantee.

// Values that are never secrets even though they flow through the same call sites. A guard that
// fires on the empty string (or on a placeholder a stand-up provisions as a non-secret) would be
// disabled within a week, so the exclusions are named here rather than at each call site.
// `postgres` is libpq's default user/db name and appears verbatim in every conninfo argv — a real
// non-secret whose risk of exemption is nil (a live credential is never the literal `postgres`).
const NON_SECRET = new Set(["", "postgres", "prisma-no-postgrest"]);

// The minimum length a value must have to be WATCHED as a secret. Risk of the floor (criterion 3 of
// #1413): a target-derived secret shorter than 8 chars would slip through un-watched. That
// population is zero for what this system actually handles — session/app JWTs, Supabase anon &
// service_role keys, DB passwords, minted bearer tokens and the seed password are all far longer.
// The floor earns its keep the other way: a 1–4 char value (a git short-flag, a status code, `main`)
// is a substring of countless benign argv elements, so watching it would fire everywhere and get the
// guard deleted — the exact failure the NON_SECRET note above warns about. MEASURED 2026-07-31: the
// shortest secret any caller registers is `harvey-pentest-pw-123456` (24 chars).
const MIN_SECRET_LEN = 8;

export function isWatchableSecret(v: string | undefined): v is string {
  return typeof v === "string" && v.length >= MIN_SECRET_LEN && !NON_SECRET.has(v);
}

// A distinct error type so a spawn REFUSAL is never mistaken for a routine failure. The stand-ups
// wrap sign-in / probe calls in try/catch that turn a bad response into `{ ok: false }`; a secret
// leaking to argv must not read as "sign-in failed" and be swallowed (criterion 4 of #1413), so
// those catches re-throw this class while still absorbing ordinary failures.
export class SecretInArgvError extends Error {}

// The enforcement point. Every spawn that has a secret ANYWHERE in scope calls this with the argv it
// is about to pass and the secrets it holds; a secret that reached argv throws before the spawn
// rather than being discovered by a later inspection. The message names the site and the argv index
// but NEVER the secret — this throws into logs Harvey writes.
export function assertNoSecretInArgv(site: string, argv: readonly string[], secrets: readonly (string | undefined)[]): void {
  const watched = secrets.filter(isWatchableSecret);
  for (const [i, arg] of argv.entries()) {
    if (watched.some((s) => arg.includes(s))) {
      throw new SecretInArgvError(
        `${site}: refusing to spawn — a secret appears in argv[${i}]. argv is world-readable via \`ps\`; ` +
          `pass the value in the child's environment or on its stdin (#1297).`,
      );
    }
  }
}

// A per-run collection of every secret in scope, so a spawn choke point (`sh`) can screen its argv
// against ALL of them without each call site re-declaring which parameter holds what. This is what
// makes the guard STRUCTURAL rather than opt-in (#1413): a new `sh` caller is covered automatically,
// and a secret embedded in an argv element the call site never thought of — a `-c` SQL string, a
// request body interpolated into a URL — is caught because the registry, not the call site, decides
// what a secret is.
export class SecretRegistry {
  private readonly secrets = new Set<string>();
  register(...values: (string | undefined)[]): void {
    for (const v of values) if (isWatchableSecret(v)) this.secrets.add(v);
  }
  clear(): void {
    this.secrets.clear();
  }
  // Throws SecretInArgvError before the spawn if any registered secret is in argv.
  assertArgvClean(site: string, argv: readonly string[]): void {
    assertNoSecretInArgv(site, argv, [...this.secrets]);
  }
  get size(): number {
    return this.secrets.size;
  }
}

// PostgreSQL 18 option vocabulary, checked against parse-only PQconninfoParse 18.4 (#1778).
// Keep this boundary explicit: a new/unknown option needs credential-transport review before use.
// sslpassword, OAuth client secrets and SCRAM keys have no PGPASSWORD equivalent and are refused.
const PG_OPTIONS = new Set((
  "service user password passfile channel_binding connect_timeout dbname host hostaddr port " +
  "client_encoding options application_name fallback_application_name keepalives keepalives_idle " +
  "keepalives_interval keepalives_count tcp_user_timeout sslmode sslnegotiation sslcompression " +
  "sslcert sslkey sslcertmode sslrootcert sslcrl sslcrldir sslsni requirepeer require_auth " +
  "min_protocol_version max_protocol_version ssl_min_protocol_version ssl_max_protocol_version " +
  "gssencmode krbsrvname gsslib gssdelegation replication target_session_attrs load_balance_hosts " +
  "oauth_issuer oauth_client_id oauth_scope sslkeylogfile"
).split(" "));

interface PgPasswordTransport {
  conninfo: string;
  password?: string;
  extractedPasswords?: string[];
}

function refusePgConninfo(): never {
  throw new SecretInArgvError("PostgreSQL credential transport: refusing malformed or unsupported conninfo before spawning; use supported UTF-8 password syntax and environment credentials (#1778).");
}

function pgUriValue(raw: string): string {
  // libpq trims literal ASCII spaces around URI components, leaves '+' literal, and decodes once.
  const trimmed = raw.replace(/^ +| +$/g, "");
  if (trimmed.includes(" ")) return refusePgConninfo();
  try {
    const value = decodeURIComponent(trimmed);
    if (value.includes("\0")) return refusePgConninfo();
    return value;
  } catch { return refusePgConninfo(); }
}

function pgOption(name: string, value: string, uri: boolean): void {
  if (!PG_OPTIONS.has(name) && !(uri && name === "ssl" && value === "true")) refusePgConninfo();
}

function withPgPasswords(conninfo: string, extractedPasswords: string[]): PgPasswordTransport {
  return extractedPasswords.length ? { conninfo, password: extractedPasswords.at(-1)!, extractedPasswords } : { conninfo };
}

function splitPgUri(conninfo: string, prefixLength: number): PgPasswordTransport {
  const passwords: string[] = [];
  let cursor = prefixLength;
  let passwordSpan: [number, number] | undefined;
  let lookahead = cursor;
  while (lookahead < conninfo.length && conninfo[lookahead] !== "@" && conninfo[lookahead] !== "/") lookahead++;
  if (conninfo[lookahead] === "@") {
    const colon = conninfo.indexOf(":", cursor);
    const hasPassword = colon >= cursor && colon < lookahead;
    pgUriValue(conninfo.slice(cursor, hasPassword ? colon : lookahead));
    if (hasPassword) {
      const raw = conninfo.slice(colon + 1, lookahead);
      // Empty userinfo is absent in libpq; query/keyword password='' is present and overrides it.
      if (raw !== "") passwords.push(pgUriValue(raw));
      passwordSpan = [colon, lookahead];
    }
    cursor = lookahead + 1;
  }

  // Walk the libpq host list without WHATWG normalization (multiple hosts and Unix sockets).
  const hosts: string[] = [];
  const ports: string[] = [];
  for (;;) {
    const hostStart = cursor;
    if (conninfo[cursor] === "[") {
      const end = conninfo.indexOf("]", cursor + 1);
      if (end <= cursor + 1) return refusePgConninfo();
      hosts.push(conninfo.slice(cursor + 1, end));
      cursor = end + 1;
      if (cursor < conninfo.length && !":/?,".includes(conninfo[cursor]!)) return refusePgConninfo();
    } else {
      while (cursor < conninfo.length && !":/?,".includes(conninfo[cursor]!)) cursor++;
      hosts.push(conninfo.slice(hostStart, cursor));
    }
    if (conninfo[cursor] === ":") {
      const portStart = ++cursor;
      while (cursor < conninfo.length && !"/?,".includes(conninfo[cursor]!)) cursor++;
      ports.push(conninfo.slice(portStart, cursor));
    } else ports.push("");
    if (conninfo[cursor] !== ",") break;
    cursor++;
  }
  // libpq decodes the joined buffers: spaces beside an interior comma are not outer whitespace.
  pgUriValue(hosts.join(","));
  pgUriValue(ports.join(","));
  if (conninfo[cursor] === "/") {
    const dbStart = ++cursor;
    while (cursor < conninfo.length && conninfo[cursor] !== "?") cursor++;
    pgUriValue(conninfo.slice(dbStart, cursor));
  }
  const queryStart = cursor;
  const retained: string[] = [];
  let removedQueryPassword = false;
  if (conninfo[cursor] === "?") {
    cursor++;
    while (cursor < conninfo.length) {
      const end = conninfo.indexOf("&", cursor);
      const pair = conninfo.slice(cursor, end === -1 ? conninfo.length : end);
      const equals = pair.indexOf("=");
      if (equals < 0 || pair.indexOf("=", equals + 1) !== -1) return refusePgConninfo();
      const name = pgUriValue(pair.slice(0, equals));
      const value = pgUriValue(pair.slice(equals + 1));
      pgOption(name, value, true);
      if (name === "password") {
        passwords.push(value);
        removedQueryPassword = true;
      } else retained.push(pair);
      cursor = end === -1 ? conninfo.length : end + 1;
    }
  }
  let base = conninfo.slice(0, queryStart);
  if (passwordSpan) base = base.slice(0, passwordSpan[0]) + base.slice(passwordSpan[1]);
  const query = removedQueryPassword ? (retained.length ? `?${retained.join("&")}` : "") : conninfo.slice(queryStart);
  return withPgPasswords(base + query, passwords);
}

function splitPgKeywords(conninfo: string): PgPasswordTransport {
  const passwords: string[] = [];
  const retained: string[] = [];
  const space = (c: string | undefined): boolean => c !== undefined && /[ \t\r\n\f\v]/.test(c);
  let cursor = 0;
  while (cursor < conninfo.length) {
    while (space(conninfo[cursor])) cursor++;
    if (cursor === conninfo.length) break;
    const start = cursor;
    while (cursor < conninfo.length && conninfo[cursor] !== "=" && !space(conninfo[cursor])) cursor++;
    const name = conninfo.slice(start, cursor);
    while (space(conninfo[cursor])) cursor++;
    if (conninfo[cursor++] !== "=") return refusePgConninfo();
    while (space(conninfo[cursor])) cursor++;
    let value = "";
    if (conninfo[cursor] === "'") {
      cursor++;
      for (;;) {
        if (cursor >= conninfo.length) return refusePgConninfo();
        const char = conninfo[cursor++]!;
        if (char === "'") break;
        if (char === "\\") {
          if (cursor >= conninfo.length) return refusePgConninfo();
          value += conninfo[cursor++]!;
        } else value += char;
      }
    } else {
      while (cursor < conninfo.length && !space(conninfo[cursor])) {
        const char = conninfo[cursor++]!;
        if (char === "\\") {
          if (cursor < conninfo.length) value += conninfo[cursor++]!;
        } else value += char;
      }
    }
    pgOption(name, value, false);
    if (name === "password") passwords.push(value);
    else retained.push(conninfo.slice(start, cursor));
  }
  return withPgPasswords(passwords.length ? retained.join(" ") : conninfo, passwords);
}

// Remove every libpq password assignment, retaining overridden values for the argv guard.
// Callers distinguish absent from empty: the final empty assignment must override PGPASSWORD too.
// Other option values retain their original spans; file/service contents and arbitrary metadata
// are outside this inline-credential boundary. Parser reference: PostgreSQL 18 libpq fe-connect.c.
export function splitPgPassword(conninfo: string): PgPasswordTransport {
  if (conninfo.includes("\0") || [...conninfo].some((c) => c.length === 1 && c.charCodeAt(0) >= 0xd800 && c.charCodeAt(0) <= 0xdfff)) return refusePgConninfo();
  if (conninfo.startsWith("postgresql://")) return splitPgUri(conninfo, "postgresql://".length);
  if (conninfo.startsWith("postgres://")) return splitPgUri(conninfo, "postgres://".length);
  if (!conninfo.includes("=") && !conninfo.includes("://")) return { conninfo };
  return splitPgKeywords(conninfo);
}

interface CurlRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string; // an already-serialized request body
  // #1673 — the body is not always JSON. Supabase Storage refuses an upload whose Content-Type is
  // not in the bucket's allowed_mime_types and answers 415 invalid_mime_type, so a hardcoded
  // application/json made every storage seed fail (MEASURED 2026-07-31: text/plain and
  // application/octet-stream refused on a bucket listing {image/png,image/jpeg,application/pdf};
  // image/png accepted).
  contentType?: string;
  writeOut?: string; // curl's -w template, when the caller needs the status code appended
  maxTimeSeconds?: number;
}

// curl reads its options from a config file, and `-K -` reads that file from stdin — so headers
// carrying a bearer token or a session cookie never become argv elements. Values are double-quoted
// and backslash-escaped, which is curl's documented quoting for config files.
//
// MEASURED 2026-07-28 against curl 8.7.1 and a local HTTP server: an apikey header, an
// `Authorization: Bearer …` header and a JSON body all round-trip byte-identically through `-K -`,
// including embedded double quotes and backslashes (src/secret-argv.test.ts).
export function curlConfig(req: CurlRequest): { argv: string[]; input: string } {
  const q = (v: string): string => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const lines = [`url = ${q(req.url)}`, `request = ${q(req.method)}`, "silent"];
  for (const [k, v] of Object.entries(req.headers)) lines.push(`header = ${q(`${k}: ${v}`)}`);
  if (req.body !== undefined) {
    lines.push(`header = ${q(`Content-Type: ${req.contentType ?? "application/json"}`)}`);
    lines.push(`data = ${q(req.body)}`);
  }
  if (req.writeOut !== undefined) lines.push(`write-out = ${q(req.writeOut)}`, `output = ${q("-")}`);
  if (req.maxTimeSeconds !== undefined) lines.push(`max-time = ${req.maxTimeSeconds}`);
  return { argv: ["-K", "-"], input: lines.join("\n") + "\n" };
}
