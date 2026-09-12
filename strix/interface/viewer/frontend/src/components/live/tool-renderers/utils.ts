export function shortPath(p: string): string {
  return p.length > 60 ? "..." + p.slice(-57) : p;
}
