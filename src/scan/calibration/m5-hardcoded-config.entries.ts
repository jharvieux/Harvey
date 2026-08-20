import type { CorpusEntry } from "./types.js";

const M5 = "M5";
const ROOT = "m5-hardcoded-deployment";

export const m5HardcodedConfigEntries: CorpusEntry[] = [
  { module: M5, id: "M5-HC-P-SERVER-ENDPOINT", kind: "positive", cls: "Deployment endpoint in server client construction", location: `${ROOT}/server-positive.ts`, match: ["hardcoded deployment endpoint"], expectedTier: "review", note: "OrdersClient receives a production-specific baseURL literal. The AST classifier names the literal, constructor consumer, and expected BASE_URL seam." },
  { module: M5, id: "M5-HC-N-SERVER-CONFIG", kind: "negative", cls: "Server endpoint sourced from validated runtime configuration", location: `${ROOT}/server-negative.ts`, note: "The same OrdersClient consumer reads env.ORDERS_BASE_URL rather than a literal; dynamic/config-backed values make no defect claim." },

  { module: M5, id: "M5-HC-P-CLIENT-ENDPOINT", kind: "positive", cls: "Deployment endpoint in browser client construction", location: `${ROOT}/client-positive.tsx`, match: ["hardcoded deployment endpoint"], expectedTier: "review", note: "A use-client telemetry constructor embeds a production ingest endpoint. It is environment coupling, not credential material, and starts at review tier." },
  { module: M5, id: "M5-HC-N-CLIENT-CANONICAL", kind: "negative", cls: "Canonical public provider URL in browser client", location: `${ROOT}/client-negative.tsx`, note: "The identical client-construction shape uses GitHub's canonical public API URL, which is not deployment-specific and stays silent." },

  { module: M5, id: "M5-HC-P-CONFIG-PROJECT", kind: "positive", cls: "Provider project identifier in deployment configuration", location: `${ROOT}/config-positive.ts`, match: ["hardcoded provider identifier"], expectedTier: "review", note: "deploymentConfig embeds a project-shaped production identifier. Evidence redacts the value while retaining its fingerprint and names CLOUD_PROJECT_ID as the seam." },
  { module: M5, id: "M5-HC-N-CONFIG-VALIDATED", kind: "negative", cls: "Provider project identifier from schema-validated environment", location: `${ROOT}/config-negative.ts`, note: "The paired deploymentConfig reads CLOUD_PROJECT_ID from a zod-validated process.env object; no literal is asserted as a defect." },

  { module: M5, id: "M5-HC-P-REQUEST-ENDPOINT", kind: "positive", cls: "Deployment endpoint passed to a request call", location: `${ROOT}/request-positive.ts`, match: ["hardcoded deployment endpoint"], expectedTier: "review", note: "fetch receives a production ledger endpoint literal, so the request node and LEDGER_BASE_URL seam are client-legible in evidence." },
  { module: M5, id: "M5-HC-N-REQUEST-DYNAMIC", kind: "negative", cls: "Request URL composed from validated runtime configuration", location: `${ROOT}/request-negative.ts`, note: "fetch receives a URL object built from a runtime path and env.LEDGER_BASE_URL. The classifier does not guess through dynamic expressions." },

  { module: M5, id: "M5-HC-P-INFRA-ACCOUNT", kind: "positive", cls: "Cloud account identifier in infrastructure-adjacent source", location: `${ROOT}/infrastructure-positive.ts`, match: ["hardcoded provider identifier"], expectedTier: "review", note: "A CloudService constructor receives a 12-digit account identifier literal. The value is redacted and ACCOUNT_ID is named as the expected seam." },
  { module: M5, id: "M5-HC-N-INFRA-CONFIG", kind: "negative", cls: "Cloud account identifier supplied by stack configuration", location: `${ROOT}/infrastructure-negative.ts`, note: "The paired infrastructure shape reads accountId through stack.require(), so no literal/provider-live-state claim is made." },
];
