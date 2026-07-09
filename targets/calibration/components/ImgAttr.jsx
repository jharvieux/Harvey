import { useEffect, useRef } from "react";
import { useRouter } from "next/router";

// PLANTED BUG (P-XSS-SETATTR): request-controlled router.query.avatar is passed to
// setAttribute("src", ...) with no scheme allowlist — an attacker can supply a javascript: URL
// that runs on load/click. Review tier: a static rule can't see whether a scheme check happens
// elsewhere.
export default function ImgAttr() {
  const ref = useRef(null);
  const router = useRouter();
  useEffect(() => {
    if (ref.current) ref.current.setAttribute("src", router.query.avatar);
  }, [router.query.avatar]);
  return <img ref={ref} alt="" />;
}
