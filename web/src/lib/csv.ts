/** A spreadsheet runs cells starting with = + - @ (or tab/CR) as formulas; indicators and feed
 *  text are attacker-controlled, so neutralise them with a leading apostrophe. */
export function safeCell(text: string): string {
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}

function quote(cell: string): string {
  return /[",\n\r]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell;
}

export function toCsv(rows: string[][]): string {
  return rows.map((r) => r.map((c) => quote(safeCell(c))).join(",")).join("\n") + "\n";
}

export function downloadText(name: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
