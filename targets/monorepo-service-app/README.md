# monorepo-service-app

Intentionally vulnerable M2 fixture for the behind-the-gateway `DIRECT-SERVICE-CALL` path. The
fronting `apps/main` app references `RAG_SERVICE_URL`; `apps/rag` exposes an ordinary
`/api/retrieve` route on a second loopback origin. No `/internal` path exists, so only monorepo
service-app discovery can classify the vulnerable endpoint. The fronting `/api/notes` route is the
negative control and must not enter `serviceEndpoints`.

Run the live proof with:

```sh
pnpm dynamic-validate targets/monorepo-service-app --execute --out /tmp/harvey-monorepo-m2
```
