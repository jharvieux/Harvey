// TRUE NEGATIVE (N-CORS-OBJLIT-ALLOWLIST, #570): the same object-literal headers map, but Access-
// Control-Allow-Origin is a specific allowlisted origin, not "*". harvey-permissive-cors's wildcard
// pattern requires the "*" literal value — cleared. Regression guard for the new object-literal shape.
export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "https://app.example.com",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};
