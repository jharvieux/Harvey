// dup/route-b.ts — PLANTED NEGATIVE (M4-N-BOILERPLATE): shares the Next.js
// API-route config + handler-signature boilerplate with route-a.ts. The
// shared span is a framework contract, not a defect, and stays under jscpd's
// 50-token minimum — must not be flagged.
export const config = {
  api: {
    bodyParser: false,
  },
};

export default function handler(req, res) {
  res.status(200).json({ route: "b", ok: true });
}
