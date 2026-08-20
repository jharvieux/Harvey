"use client";

import { useSearchParams } from "next/navigation";

export function parseBrowserXml() {
  const searchParams = useSearchParams();
  return new DOMParser().parseFromString(searchParams.get("xml") ?? "", "application/xml");
}
