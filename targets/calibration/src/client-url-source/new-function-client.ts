"use client";

import { useSearchParams } from "next/navigation";

export function compileUrlExpression() {
  const searchParams = useSearchParams();
  return new Function(searchParams.get("expression"))();
}
