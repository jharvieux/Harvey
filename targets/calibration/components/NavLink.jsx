import Link from "next/link";

// N-HREF-INTERNAL (NEGATIVE — must NOT be flagged): href is a constant internal route via
// next/link's <Link>, not request-derived and not a native <a>. harvey-href-js-url's sink is a
// native <a href={...}>; a constant string on <Link> matches neither the element nor the taint
// source.
export default function NavLink() {
  return <Link href="/dashboard">Dashboard</Link>;
}
