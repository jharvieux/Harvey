// pages/dead-page.js — PLANTED NEGATIVE (M5-N-NEXT-MAGIC): a Next.js Pages
// Router page. Next calls the default export and getServerSideProps by
// routing/build convention, never via a static import. knip's built-in
// Next.js plugin (auto-detected from the `next` dependency) treats
// pages/**/*.{js,jsx,ts,tsx} as entry points, so neither export is flagged.
export async function getServerSideProps() {
  return { props: { generatedAt: Date.now() } };
}

export default function DeadPage({ generatedAt }) {
  return `dead-page rendered at ${generatedAt}`;
}
