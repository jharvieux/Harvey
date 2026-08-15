"use client";

import { useSearchParams } from "next/navigation";
import * as XLSX from "xlsx";

export function exportXlsxSheet() {
  const searchParams = useSearchParams();
  return XLSX.utils.aoa_to_sheet([[searchParams.get("label")]]);
}
