import { useEffect, useRef } from "react";
import { useRouter } from "next/router";

export default function ScopeControl() {
  const ref = useRef(null);
  const router = useRouter();
  useEffect(() => {
    if (ref.current) ref.current.innerHTML = router.query.q;
  }, [router.query.q]);
  return <div ref={ref} />;
}
