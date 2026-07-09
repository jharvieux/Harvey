// N-JSX-KEY (NEGATIVE — must NOT be flagged): a composite, stable React key
// (`${item.id}-${index}`). Sonar S6479 over-fires on any key containing an index, but a key
// combining a stable id with the index is fine. React-key/quality rules stay out of the
// security count entirely regardless.
export default function List({ items }) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={`${item.id}-${index}`}>{item.label}</li>
      ))}
    </ul>
  );
}
