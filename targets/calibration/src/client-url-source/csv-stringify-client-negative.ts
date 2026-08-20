"use client";

import { stringify } from "csv-stringify/sync";
import { useSearchParams } from "next/navigation";

export function unsupportedClientStringify() {
  const searchParams = useSearchParams();
  return stringify([{ label: searchParams.get("label") }]);
}
