// UTF-8 bytes preserve the complete finding identity without slug collisions or order dependence.
import { Buffer } from "node:buffer";

export const findingAnchor = (id) => `finding-${Buffer.from(id, "utf8").toString("hex")}`;
export const findingIdAttribute = (id) => String(id).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

export function assertFindingNavigation(html) {
  const destinations = new Map();
  for (const match of html.matchAll(/\bid="(finding-[^"]+)"\s+data-finding-id="([^"]*)"/g)) {
    if (destinations.has(match[1])) throw new Error(`Duplicate finding destination: ${match[1]}`);
    destinations.set(match[1], match[2]);
  }
  for (const match of html.matchAll(/<a\s+class="finding-link"\s+href="#([^"]+)"\s+data-finding-link="([^"]*)"/g)) {
    if (destinations.get(match[1]) !== match[2]) {
      throw new Error(`Finding link has no unique intended detail: ${match[2]} -> ${match[1]}`);
    }
  }
}
