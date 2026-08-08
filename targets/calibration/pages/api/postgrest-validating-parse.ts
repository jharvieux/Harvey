import { parseDateTime, toCalendarDateTime } from "@internationalized/date";
import { admin } from "../../lib/supabaseAdmin";

export default async function handler(req: any, res: any) {
  const start = String(req.query.start);
  const startDate = toCalendarDateTime(parseDateTime(start));
  const previousEnd = startDate.add({ days: -1 });
  const { data } = await admin
    .from("productionKpi")
    .select("id")
    .or(`endTime.lte.${previousEnd.toString()},endTime.is.null`);

  res.status(200).json(data);
}
