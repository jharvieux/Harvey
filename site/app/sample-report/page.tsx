import SampleReportClient from "./SampleReportClient";

export const metadata = {
  title: "Sample report — what a Harvey audit looks like",
  description:
    "A full sample Harvey audit report: the readiness verdict, findings ranked by blast radius across all ten modules, each with evidence and a named fix, and the coverage ledger showing what ran and what didn't. Synthetic demonstration data.",
  alternates: { canonical: "/sample-report" },
  openGraph: {
    title: "Sample report — what a Harvey audit looks like",
    description: "The readiness verdict, ranked findings with named fixes, and the coverage ledger. Synthetic demo data.",
    url: "https://harvey-qa.com/sample-report",
    type: "article",
  },
};

export default function SampleReport() {
  return <SampleReportClient />;
}
