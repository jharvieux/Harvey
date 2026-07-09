import { useEffect, useRef } from "react";
import { useRouter } from "next/router";

// PLANTED BUG (P-DOM-XSS-INNERHTML): request-controlled router.query.q flows straight into
// .innerHTML — DOM XSS. No-unsanitized-class precision (~100%): an innerHTML assignment from a
// clearly tainted request source, no sanitizer in between. High tier (free count).
export default function Widget() {
  const ref = useRef(null);
  const router = useRouter();
  useEffect(() => {
    if (ref.current) ref.current.innerHTML = router.query.q;
  }, [router.query.q]);
  return <div ref={ref} />;
}
