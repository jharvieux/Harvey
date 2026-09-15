import { credentialSecretsFromHeaders, redactConfiguredSecrets, redactJsonStrings } from "../secret-redact.js";

// Shared HTTP helper for the tracker adapters. Upstreams and proxies sometimes echo request
// credentials, so omitting request headers from our own error shape is insufficient. Derive the
// sensitive values from the request headers at this boundary and scrub response bodies, successful
// JSON payloads, and transport exceptions before any adapter or persistence consumer sees them.

export class TrackerError extends Error {
  constructor(
    readonly method: string,
    readonly url: string,
    readonly status: number,
    readonly responseBody: string,
    // #747: the server's Retry-After (in ms), when it sent one on a 429/secondary-rate-limit. Lets
    // the pacer honor the advised wait instead of guessing. Undefined ⇒ no header, pacer backs off.
    readonly retryAfterMs?: number,
  ) {
    super(`${method} ${url} -> ${status}: ${responseBody.slice(0, 500)}`);
    this.name = "TrackerError";
  }
}

class TrackerTransportError extends Error {
  constructor(
    readonly method: string,
    readonly url: string,
    readonly detail: string,
  ) {
    super(`${method} ${url} transport error: ${detail}`);
    this.name = "TrackerTransportError";
  }
}

// Parse a Retry-After header (RFC 7231: delta-seconds or an HTTP-date) into milliseconds. Returns
// undefined when absent or unparseable — the pacer then falls back to exponential backoff.
function parseRetryAfter(res: Response): number | undefined {
  const raw = res.headers.get("retry-after");
  if (!raw) return undefined;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(raw);
  return Number.isNaN(when) ? undefined : Math.max(0, when - Date.now());
}

interface TrackerRequest {
  method: string;
  headers: Record<string, string>;
  body?: string | FormData;
}

export async function trackerFetch(fetchImpl: typeof fetch, url: string, req: TrackerRequest): Promise<Response> {
  const secrets = credentialSecretsFromHeaders(req.headers);
  const safeUrl = redactConfiguredSecrets(url, secrets);
  let res: Response;
  try {
    res = await fetchImpl(url, req);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new TrackerTransportError(req.method, safeUrl, redactConfiguredSecrets(detail, secrets));
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new TrackerError(req.method, safeUrl, res.status, redactConfiguredSecrets(body, secrets), parseRetryAfter(res));
  }
  return res;
}

export async function trackerFetchJson<T>(fetchImpl: typeof fetch, url: string, req: TrackerRequest): Promise<T> {
  const res = await trackerFetch(fetchImpl, url, req);
  const secrets = credentialSecretsFromHeaders(req.headers);
  try {
    return redactJsonStrings(await res.json(), secrets) as T;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new TrackerTransportError(req.method, redactConfiguredSecrets(url, secrets), redactConfiguredSecrets(`invalid JSON response: ${detail}`, secrets));
  }
}
