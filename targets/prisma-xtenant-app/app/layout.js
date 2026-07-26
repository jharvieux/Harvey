// Minimal root layout so `next build` succeeds for this API-only fixture (#1163).
export const metadata = { title: "prisma-xtenant-app" };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
