export const num = (n: number | undefined) => (n ?? 0).toLocaleString("en-US");

export function bytes(n: number) {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;

  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} kB`;

  return `${n} B`;
}

export const date = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : "–");

export const epoch = (seconds: number | null) =>
  seconds ? date(new Date(seconds * 1000).toISOString()) : "–";

export function ago(iso: string) {
  const hours = Math.round((Date.now() - Date.parse(iso)) / 3_600_000);

  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

// URLs come from CAs: only link to http(s)
export const safeUrl = (url: string | undefined) =>
  url && /^https?:\/\//i.test(url) ? url : undefined;

export const crtsh = (query: string) => `https://crt.sh/?q=${encodeURIComponent(query)}`;
