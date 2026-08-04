// Slim, dependency-free extract of strix-app's display-number helper. The full
// version queries Supabase to compute org-wide finding numbers; the local viewer
// only ever needs the pure formatter, so the supabase-backed functions are
// intentionally omitted (a local run has no org context).
export function formatStrixId(num: number): string {
  return `STRIX-${num}`;
}

/** Format an integer with locale thousands separators (e.g. 68339486 -> "68,339,486"). */
export function formatNumber(num: number): string {
  return new Intl.NumberFormat("en-US").format(num);
}
