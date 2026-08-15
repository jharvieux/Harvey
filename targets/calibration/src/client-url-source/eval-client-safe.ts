"use client";

import { useSearchParams } from "next/navigation";

export function parseClientExpression() {
  const searchParams = useSearchParams();
  const expression = searchParams.get("expression") ?? "null";
  return JSON.parse(expression) as unknown;
}
