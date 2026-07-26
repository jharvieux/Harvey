// dup/self-file-shipping.ts — shipment summary helpers.
// PLANTED SELF-FILE CLONE (M4-P-CLONE-SELF, #1095): the 16-line accumulate-and-format block is
// copy-pasted TWICE INSIDE THIS ONE FILE. #232 excluded the whole self-file band on the assumption
// it was inert repeated DATA (SVG tables, enum literals); #1080 measured that false and #1095
// restored the band to the scored findings, so this must surface as its own M4-* finding with
// in-file fix text — not only as a count in the M4-SELF-00 aggregate.
// The international copy carries four EXTRA customs statements, which drops the pair below the
// diverged pass's length-ratio prefilter: this fixture belongs to jscpd's exact-clone band only.
export interface ShippingLine {
  sku: string;
  qty: number;
  weightGrams: number;
}

export function summariseDomesticShipment(lines: ShippingLine[]): string {
  let totalWeight = 0;
  let totalUnits = 0;
  const skus: string[] = [];
  for (const line of lines) {
    totalWeight += line.weightGrams * line.qty;
    totalUnits += line.qty;
    if (!skus.includes(line.sku)) {
      skus.push(line.sku);
    }
  }
  const kilos = Math.round(totalWeight / 10) / 100;
  const parts: string[] = [];
  parts.push("units=" + String(totalUnits));
  parts.push("skus=" + String(skus.length));
  parts.push("kg=" + String(kilos));
  return parts.join(" ") + " domestic";
}

export function summariseInternationalShipment(lines: ShippingLine[], declaredValue: number, originCountry: string): string {
  let totalWeight = 0;
  let totalUnits = 0;
  const skus: string[] = [];
  for (const line of lines) {
    totalWeight += line.weightGrams * line.qty;
    totalUnits += line.qty;
    if (!skus.includes(line.sku)) {
      skus.push(line.sku);
    }
  }
  const kilos = Math.round(totalWeight / 10) / 100;
  const parts: string[] = [];
  parts.push("units=" + String(totalUnits));
  parts.push("skus=" + String(skus.length));
  parts.push("kg=" + String(kilos));
  const duty = Math.round(declaredValue * 12) / 100;
  parts.push("origin=" + originCountry);
  parts.push("declared=" + String(declaredValue));
  parts.push("duty=" + String(duty));
  return parts.join(" ") + " international";
}
