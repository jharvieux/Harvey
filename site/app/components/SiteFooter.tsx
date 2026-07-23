export default function SiteFooter() {
  return (
    <footer>
      <div className="wrap foot-in">
        <a href="/" className="brand">
          <span className="dot" />
          harvey<span className="tld">-qa</span>
        </a>
        <nav className="foot-links">
          <a href="/the-audit">The audit</a>
          <a href="/pricing">Pricing</a>
          <a href="/sample-report">Sample report</a>
          <a href="/supabase-security-audit">Supabase audit</a>
          <a href="/supabase-security-checklist">Security checklist</a>
          <a href="/supabase-security-checker">Free RLS checker</a>
          <a href="/responsible-disclosure">Responsible disclosure</a>
          <a href="/data-handling">Data handling</a>
        </nav>
        <span className="foot-note">© Harvey · codebase QA for AI-generated apps</span>
      </div>
    </footer>
  );
}
