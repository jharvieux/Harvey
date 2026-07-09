"use client";

// Client Component: renders whatever props it's given. If a caller spreads a raw DB row into
// this component (see app/documents/detail-page.tsx), every column on that row — not just the
// two rendered here — serializes into the RSC payload sent to the browser.
export function DocumentCard(props) {
  return (
    <div>
      <h2>{props.title}</h2>
      <p>{props.updated_at}</p>
    </div>
  );
}
