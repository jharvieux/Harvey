// Root layout. Not a planted bug and not a negative control — the App Router requires exactly one
// of these for the tree to build at all, and without it `next build` fails with "admin/page.tsx
// doesn't have a root layout", which is what kept this target unbootable by its own live M2 pipeline
// (#1672). Deliberately inert: no auth, no data access, no headers.
export const metadata = { title: "Harvey calibration target" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
