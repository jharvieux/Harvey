export const metadata = { title: "vuln-seam-app", description: "Harvey M2 seam fixture — do not deploy" };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
