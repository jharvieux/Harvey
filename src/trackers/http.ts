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
  ) {
    super(`${method} ${url} -> ${status}: ${responseBody.slice(0, 500)}`);
    this.name = "TrackerError";
  }
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
    throw new TrackerError(req.method, url, res.status, body);
  }
  return res;
}

export async function trackerFetchJson<T>(fetchImpl: typeof fetch, url: string, req: TrackerRequest): Promise<T> {
  const res = await trackerFetch(fetchImpl, url, req);
  return (await res.json()) as T;
}
