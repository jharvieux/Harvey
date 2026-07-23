// Shared HTTP helper for the tracker adapters. Kept small on purpose: it makes the request and,
// on a non-2xx response, throws a TrackerError carrying only method/url/status and the RESPONSE
// body — never the request headers. The injected credential lives in an Authorization header, so
// keeping headers out of the error (and out of every log line) is what stops the token from
// leaking into an error message or a caught-and-logged failure (credentials.test.ts asserts this).

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
  const res = await fetchImpl(url, req);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new TrackerError(req.method, url, res.status, body, parseRetryAfter(res));
  }
  return res;
}

export async function trackerFetchJson<T>(fetchImpl: typeof fetch, url: string, req: TrackerRequest): Promise<T> {
  const res = await trackerFetch(fetchImpl, url, req);
  return (await res.json()) as T;
}
