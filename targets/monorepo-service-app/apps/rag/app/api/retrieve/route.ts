export async function GET() {
  return Response.json([{ id: "private-chunk", text: "behind-the-gateway data" }]);
}
