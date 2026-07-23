export function formatCreatedAt(created: Date): string {
  const month = String(created.getMonth() + 1).padStart(2, "0");
  const day = String(created.getDate()).padStart(2, "0");
  return `${created.getFullYear()}-${month}-${day}`;
}

export function formatInvoiceDate(issued: Date): string {
  return issued.toISOString().slice(0, 10);
}

export function formatExportStamp(exported: Date): string {
  return new Intl.DateTimeFormat("en-CA", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(exported);
}
