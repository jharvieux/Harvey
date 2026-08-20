"use client";

import { writeToString } from "@fast-csv/format";
import { useSearchParams } from "next/navigation";

export function unsupportedClientFastCsv() {
  const searchParams = useSearchParams();
  return writeToString([{ label: searchParams.get("label") }]);
}
