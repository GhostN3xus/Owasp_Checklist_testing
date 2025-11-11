export function generateCSV(
  headers: string[],
  rows: (string | number | boolean | null | undefined)[][]
): string {
  const headerRow = headers.map(escapeCSV).join(",");
  const dataRows = rows.map((row) => row.map(escapeCSV).join(","));

  return [headerRow, ...dataRows].join("\n");
}

function escapeCSV(value: any): string {
  if (value === null || value === undefined) {
    return "";
  }

  const stringValue = String(value);

  if (
    stringValue.includes(",") ||
    stringValue.includes('"') ||
    stringValue.includes("\n")
  ) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }

  return stringValue;
}

export function assessmentToCSV(assessment: any): string {
  const headers = [
    "Item Code",
    "Item Title",
    "Category",
    "Status",
    "Severity",
    "Notes",
  ];

  const rows = assessment.items.map((item: any) => [
    item.item.code,
    item.item.title,
    item.item.category,
    item.status,
    item.item.severity,
    item.notes || "",
  ]);

  return generateCSV(headers, rows);
}
