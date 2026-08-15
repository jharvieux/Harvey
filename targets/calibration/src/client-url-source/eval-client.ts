"use client";

import { useSearchParams } from "next/navigation";

export function evaluateUrlExpression() {
  const searchParams = useSearchParams();
  return eval(searchParams.get("expression"));
}
