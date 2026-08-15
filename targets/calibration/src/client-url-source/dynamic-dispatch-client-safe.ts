"use client";

import { useSearchParams } from "next/navigation";

const actions = {
  preview: () => "preview",
  download: () => "download",
};

export function dispatchAllowedUrlAction() {
  const searchParams = useSearchParams();
  const action = searchParams.get("action");
  if (action !== "preview" && action !== "download") return "unsupported";
  const selected = action === "preview" ? actions.preview : actions.download;
  return selected();
}
