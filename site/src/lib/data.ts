// Loads the explorer data published next to the site (see src/explorer.ts):
// the latest build under latest/, every build under builds/<sequence>/.

import type {
  ExplorerMeta,
  ExplorerRecord,
  IssuerDetail,
  IssuerEntry,
} from "opencrlset/explorer-format";
import { sha256Hex } from "./cert.ts";

export const REPOSITORY = "https://github.com/imputnet/opencrlset";

// relative, so the site works from any path; hash routing keeps the page at /
export const latestUrl = (path: string) => `./latest/${path}`;
export const buildUrl = (sequence: number, path: string) => `./builds/${sequence}/${path}`;

const cache = new Map<string, Promise<unknown>>();

function cached<T>(key: string, load: () => Promise<T>): Promise<T> {
  // each key only ever holds what its own loader returned
  let promise = cache.get(key) as Promise<T> | undefined;

  if (!promise) {
    promise = load();
    // a failure (offline, say) shouldn't stick
    promise.catch(() => cache.delete(key));
    cache.set(key, promise);
  }

  return promise;
}

// null when the file doesn't exist; R2 answers 403 or 404 for that
async function fetchOrNull<T>(
  url: string,
  parse: (response: Response) => Promise<T>,
): Promise<T | null> {
  const response = await fetch(url);

  if (response.status === 404 || response.status === 403) return null;

  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);

  return parse(response);
}

// the build writes these files with explorer-format's types
const explorerJson = <T>(path: string) =>
  cached(path, () => fetchOrNull(latestUrl(`explorer/${path}`), (r) => r.json() as Promise<T>));

export async function meta(): Promise<ExplorerMeta> {
  const value = await explorerJson<ExplorerMeta>("meta.json");

  if (!value) throw new Error("No build has been published yet.");

  return value;
}

export const issuers = async () => (await explorerJson<IssuerEntry[]>("issuers.json")) ?? [];
export const issuer = (spki: string) => explorerJson<IssuerDetail>(`issuers/${spki}.json`);

export async function issuersBySpki(): Promise<Map<string, IssuerEntry>> {
  return cached(
    "issuers-by-spki",
    async () => new Map((await issuers()).map((entry) => [entry.spki, entry])),
  );
}

// Shards are gzip files; a server that sends them with Content-Encoding has
// already decompressed them, so check the magic bytes.
async function gunzipText(response: Response): Promise<string> {
  const bytes = new Uint8Array(await response.arrayBuffer());

  if (bytes[0] !== 0x1f || bytes[1] !== 0x8b) return new TextDecoder().decode(bytes);

  return new Response(
    new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")),
  ).text();
}

// Every revocation record for a canonical hex serial, across issuers.
export async function lookupSerial(serial: string): Promise<ExplorerRecord[]> {
  const { shardHexDigits } = await meta();
  const shard = (await sha256Hex(serial)).slice(0, shardHexDigits);

  const text = await cached(`shard/${shard}`, () =>
    fetchOrNull(latestUrl(`explorer/revocations/${shard}.ndjson.gz`), gunzipText),
  );

  if (!text) return [];
  const needle = `,"${serial}",`;

  return (
    text
      .split("\n")
      .filter((line) => line.includes(needle))
      // lines the build wrote as ExplorerRecords
      .map((line) => JSON.parse(line) as ExplorerRecord)
      .filter((record) => record[1] === serial)
  );
}
