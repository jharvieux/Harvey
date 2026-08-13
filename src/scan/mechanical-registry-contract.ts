import type { Finding } from "../findings.js";

function taxonomyIsOwned(declared: readonly string[], taxonomy: string): boolean {
  return declared.some((owned) => owned === taxonomy
    || (owned.endsWith("*") && taxonomy.startsWith(owned.slice(0, -1)))
    || owned === "Semgrep rule check_id/harveyTaxonomy from the resolved rule inputs"
    || owned === "input finding taxonomy preserved");
}

export function assertProducerTaxonomyOwnership(producer: { id: string; phase: string; taxonomies: readonly string[] }, findings: readonly Finding[]): void {
  const unknown = [...new Set(findings.map((finding) => finding.taxonomy).filter((taxonomy) => !taxonomyIsOwned(producer.taxonomies, taxonomy)))];
  if (unknown.length > 0) throw new Error(`${producer.phase}:${producer.id}: emitted unknown taxonomies [${unknown.join(", ")}]`);
}
