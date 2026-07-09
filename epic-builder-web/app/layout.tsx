import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "Harvey — Epic Builder",
  description: "Turn a one-paragraph idea into a published epic + user-story set.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
