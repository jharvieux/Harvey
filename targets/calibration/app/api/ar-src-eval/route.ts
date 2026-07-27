// PLANTED BUG (P-EVAL-SEARCHPARAMS, #1221): the expression is read via the split
// `const u = new URL(req.url); u.searchParams.get(...)` form and evaluated. harvey-code-injection-eval
// was one of the 19 of 21 rules blind to searchParams.get, so this was silent before #1221.
export async function GET(req: Request) {
  const u = new URL(req.url);
  const expr = u.searchParams.get("expr") ?? "0";
  return Response.json({ value: eval(expr) });
}
