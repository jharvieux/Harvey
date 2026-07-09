import { z } from "zod";

// N-URL-ENV (NEGATIVE — must NOT be flagged): z.string().url() on a trusted operator/env
// config value, which is legitimately non-http (redis://). Open-redirect/SSRF URL rules must
// target USER-ingested URLs (source_url, avatar_url, ?url=...), not operator env config
// (docs/fp-rules.txt: operator/env config URLs are exempt).
const RedisConfig = z.object({ url: z.string().url() });

export function redisUrl() {
  return RedisConfig.parse({ url: process.env.REDIS_URL }).url;
}
