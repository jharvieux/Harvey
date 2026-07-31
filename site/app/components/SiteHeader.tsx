"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

export default function SiteHeader() {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);

  useEffect(() => {
    if (theme) {
      document.documentElement.setAttribute("data-theme", theme);
      try {
        localStorage.setItem("harvey-theme", theme);
      } catch {}
    }
  }, [theme]);

  const toggleTheme = () =>
    setTheme((prev) => {
      const cur = prev ?? (document.documentElement.getAttribute("data-theme") as "light" | "dark" | null);
      const active = cur ?? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      return active === "dark" ? "light" : "dark";
    });

  return (
    <header className="nav">
      <div className="wrap nav-in">
        <Link href="/" className="brand">
          <span className="dot" />
          harvey<span className="tld">-qa</span>
        </Link>
        <nav className="nav-links">
          <a href="/the-audit">The audit</a>
          <a href="/pricing">Pricing</a>
          <a href="/sample-report">Sample report</a>
          <button className="theme-toggle" aria-label="Toggle light or dark theme" onClick={toggleTheme}>
            ◐
          </button>
          <Link href="/#scan" className="btn btn-primary">
            Run the free scan
          </Link>
        </nav>
      </div>
    </header>
  );
}
