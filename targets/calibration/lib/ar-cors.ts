// PLANTED BUG (P-CORS-WILDCARD-OBJLIT, #570): the wildcard Access-Control-Allow-Origin is declared in
// an object-literal headers map (the App Router idiom) rather than via res.setHeader — then spread
// into NextResponse.json(body, { headers: CORS_HEADERS }) on every response. harvey-permissive-cors's
// object-literal shape catches the wildcard at the literal itself. high (free count).
export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};
