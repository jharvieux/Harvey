import type { Metadata } from "next";
import "./globals.css";

const title = "Harvey — Codebase QA for AI-Generated Apps";
const description =
  "Harvey is codebase QA for AI-generated apps — a senior quality leader in a box, and an independent review of the code your AI wrote. A ten-module audit across security, tests, performance, data, and maintainability, with deep checks for Supabase, Next.js, and Vite. One readiness verdict. Start free.";

export const metadata: Metadata = {
  metadataBase: new URL("https://harvey-qa.com"),
  title,
  description,
  keywords: [
    "AI generated code audit",
    "AI code security audit",
    "vibe coding security",
    "codebase QA",
    "supabase security audit",
    "next.js security audit",
    "supabase RLS audit",
    "vite app security",
  ],
  alternates: { canonical: "/" },
  openGraph: {
    title,
    description,
    url: "https://harvey-qa.com",
    siteName: "Harvey",
    type: "website",
  },
  twitter: { card: "summary_large_image", title, description },
  icons: { icon: "/favicon.svg" },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": "https://harvey-qa.com/#org",
      name: "Harvey",
      url: "https://harvey-qa.com",
      description: "Codebase QA for AI-generated apps, with deep checks for Supabase, Next.js, and Vite.",
    },
    {
      "@type": "WebSite",
      "@id": "https://harvey-qa.com/#site",
      url: "https://harvey-qa.com",
      name: "Harvey",
      publisher: { "@id": "https://harvey-qa.com/#org" },
    },
    {
      "@type": "Service",
      name: "Harvey codebase audit",
      provider: { "@id": "https://harvey-qa.com/#org" },
      serviceType: "Codebase security and quality audit",
      areaServed: "Worldwide",
      description:
        "A ten-module audit of AI-generated apps (deep on Supabase, Next.js, and Vite) across security, tests, performance, data, and maintainability, delivered as one readiness verdict.",
      offers: [
        { "@type": "Offer", name: "Free scan", price: "0", priceCurrency: "USD" },
        {
          "@type": "Offer",
          name: "Connected audit",
          priceSpecification: { "@type": "PriceSpecification", minPrice: "500", priceCurrency: "USD" },
        },
        {
          "@type": "Offer",
          name: "Full audit",
          priceSpecification: { "@type": "PriceSpecification", minPrice: "1000", priceCurrency: "USD" },
        },
      ],
    },
    {
      "@type": "FAQPage",
      mainEntity: [
        {
          "@type": "Question",
          name: "Is the Supabase anon key supposed to be public?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes — the anon key is public by design. Your security comes from Row-Level Security, not from hiding the key. If RLS is missing or misconfigured, that public key becomes a master key to your database, which is the single most common failure we find.",
          },
        },
        {
          "@type": "Question",
          name: "Isn't a scanner enough to check my app?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "A scanner checks patterns and known CVEs. It cannot tell whether your users can read each other's data, because that depends on your authorization logic across multiple files. Harvey reviews the whole codebase across ten modules and, on the paid tiers, stands up your stack to prove findings live.",
          },
        },
        {
          "@type": "Question",
          name: "How much does a Harvey audit cost?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "The free scan is $0. Paid audits are priced by codebase size, measured automatically during the free scan: a Connected audit starts at $500 and a Full audit (which stands up and attacks a copy of your stack) starts at $1,000. Enterprise and regulated codebases are custom-quoted.",
          },
        },
        {
          "@type": "Question",
          name: "Do you need access to my database?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Not for the free scan — it runs on source only, no credentials. The Connected and Full audits read your production database read-only to confirm live state; if you decline, those checks are recorded as not run in the coverage ledger and the rest still runs.",
          },
        },
      ],
    },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
        <noscript>
          <style>{`.sc-row{opacity:1!important;transform:none!important}`}</style>
        </noscript>
        {children}
      </body>
    </html>
  );
}
