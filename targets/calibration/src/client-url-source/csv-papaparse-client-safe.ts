"use client";

import Papa from "papaparse";
import { useSearchParams } from "next/navigation";

export function exportStaticColumns() {
  const searchParams = useSearchParams();
  void searchParams.get("column");
  return Papa.unparse([["name", "email"]]);
}
