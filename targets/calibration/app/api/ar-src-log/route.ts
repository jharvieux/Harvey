// PLANTED BUG (P-LOG-SEARCHPARAMS, #1221): the query value is logged unescaped — CR/LF log forging.
// harvey-log-injection was blind to searchParams.get before #1221.
export async function GET(req: Request) {
  const user = new URL(req.url).searchParams.get("u");
  console.log(`page view by ${user}`);
  return new Response("ok");
}
