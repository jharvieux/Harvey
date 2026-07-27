'use client';

// The Client Component the two boundary fixtures render into. It exists so the boundary the sheet
// is about is actually EXPRESSIBLE: "crosses into a Client Component" is a claim about the imported
// module's directive, so without this file the import does not resolve and the pair below tests
// nothing. It renders two fields — the shape the safe form passes, and the reason every other field
// on a whole row is pure payload weight and exposure.
export function ClientProfile(props: { name?: string; avatarUrl?: string; user?: { name: string; avatarUrl: string } }) {
  const name = props.name ?? props.user?.name;
  const avatarUrl = props.avatarUrl ?? props.user?.avatarUrl;
  return (
    <figure>
      <img src={avatarUrl} alt="" />
      <figcaption>{name}</figcaption>
    </figure>
  );
}
