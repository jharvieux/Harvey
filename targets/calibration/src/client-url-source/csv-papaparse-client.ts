"use client";

import Papa from "papaparse";
import { useSearchParams } from "next/navigation";

export function exportPapaCsv() {
  const searchParams = useSearchParams();
  return Papa.unparse([{ label: searchParams.get("label") }]);
}
