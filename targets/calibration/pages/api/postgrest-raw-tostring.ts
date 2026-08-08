import { admin } from "../../lib/supabaseAdmin";

export default async function handler(req: any, res: any) {
  const start = String(req.query.start);
  const raw = start.toString();
  const { data } = await admin
    .from("productionKpi")
    .select("id")
    .or(`endTime.lte.${raw},endTime.is.null`);

  res.status(200).json(data);
}
