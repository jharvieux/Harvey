// PLANTED BUG (P-GCP-API-KEY): a Google API key (AIza… prefix) hardcoded in source. Committed
// Google keys are frequently over-scoped (Maps + other Cloud APIs) and billable. Value is FAKE.
// gitleaks gcp-api-key pattern-matches the AIza shape → review (a fake can't be verified live).
const MAPS_API_KEY = "AIzaSyD0FAKEkeyNotReal000000000000abcde";

// NEGATIVE (N-GCP-KEY-ENV): the key read from the environment, the correct pattern — no AIza
// literal in source, so the gcp-api-key rule matches nothing here. Cleared.
const MAPS_API_KEY_SAFE = process.env.GOOGLE_MAPS_API_KEY;

export function mapsClient() {
  return { key: MAPS_API_KEY, safeKey: MAPS_API_KEY_SAFE };
}
