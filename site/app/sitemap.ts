import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://harvey-qa.com",
      changeFrequency: "weekly",
      priority: 1,
    },
  ];
}
