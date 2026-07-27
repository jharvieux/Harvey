import { useEffect, useRef } from "react";

// PLANTED BUG (P-XSS-SEARCH-SETATTR, #1223): the raw query STRING (location.search, read without
// URLSearchParams) drives setAttribute("href"). harvey-set-attribute-xss saw `$SP.get(...)` but
// not the raw-string read, so a component that parses the query itself went dark.
export default function SearchAttr() {
  const ref = useRef(null);
  useEffect(() => {
    ref.current.setAttribute("href", location.search.replace("?to=", ""));
  }, []);
  return <a ref={ref}>continue</a>;
}
