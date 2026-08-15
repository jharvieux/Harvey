"use client";

import { useSearchParams } from "next/navigation";

const actions = {
  preview: () => "preview",
  download: () => "download",
};

export function dispatchUrlAction() {
  const searchParams = useSearchParams();
  return actions[searchParams.get("action")]();
}
