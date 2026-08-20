"use client";

import { Parser } from "json2csv";
import { useSearchParams } from "next/navigation";

export function unsupportedClientJson2csv() {
  const searchParams = useSearchParams();
  return new Parser({ fields: ["label"] }).parse([{ label: searchParams.get("label") }]);
}
