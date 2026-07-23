import type { MetadataRoute } from "next";

const base = "https://harvey-qa.com";

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  const routes: { path: string; priority: number; changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"] }[] = [
    { path: "/", priority: 1, changeFrequency: "weekly" },
    { path: "/the-audit", priority: 0.9, changeFrequency: "monthly" },
    { path: "/pricing", priority: 0.9, changeFrequency: "monthly" },
    { path: "/sample-report", priority: 0.8, changeFrequency: "monthly" },
    { path: "/supabase-security-audit", priority: 0.9, changeFrequency: "monthly" },
    { path: "/supabase-security-checklist", priority: 0.8, changeFrequency: "monthly" },
    { path: "/supabase-security-checker", priority: 0.8, changeFrequency: "monthly" },
    { path: "/multi-tenant-security-supabase", priority: 0.8, changeFrequency: "monthly" },
    { path: "/responsible-disclosure", priority: 0.4, changeFrequency: "yearly" },
    { path: "/data-handling", priority: 0.4, changeFrequency: "yearly" },
  ];
  return routes.map((r) => ({ url: `${base}${r.path}`, lastModified: now, changeFrequency: r.changeFrequency, priority: r.priority }));
}
