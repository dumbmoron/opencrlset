import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { ccadbReports, loadCcadb, type Report } from "./ccadb.ts";
import { Semaphore, download } from "./net.ts";

export interface ReportSource {
  name: string;
  url: string;
  file: string;
  sha256: string;
  size: number;
}

export interface CrlSource {
  url: string;
  // CCADB records that disclose this URL
  issuers: string[];
  partitioned: boolean;
  fetchedAt?: string;
  status?: number;
  finalUrl?: string;
  sha256?: string;
  size?: number;
  attempts?: number;
  error?: string;
}

export interface Manifest {
  format: 1;
  snapshotTime: string;
  tool: { commit?: string; node: string };
  ccadb: ReportSource[];
  crls: CrlSource[];
}

export const crlPath = (snapshotDir: string, sha256: string) =>
  join(snapshotDir, "crls", `${sha256}.crl`);

export async function readManifest(snapshotDir: string): Promise<Manifest> {
  const manifest: Manifest = JSON.parse(await readFile(join(snapshotDir, "manifest.json"), "utf8"));

  if (manifest.format !== 1) throw new Error(`unsupported snapshot format ${manifest.format}`);

  return manifest;
}

export function reportsOf(manifest: Manifest): Report[] {
  return manifest.ccadb.map(({ name, url, file }) => ({ name, url, file }));
}

function toolCommit(): string | undefined {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;

  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: import.meta.dirname,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return undefined;
  }
}

export interface SnapshotOptions {
  concurrency: number;
  perHost: number;
  log: (message: string) => void;
}

export async function snapshot(dir: string, options: SnapshotOptions): Promise<Manifest> {
  const now = new Date();
  // whole seconds, so the derived CRLSet sequence and expiry are exact
  now.setUTCMilliseconds(0);
  await mkdir(join(dir, "ccadb"), { recursive: true });
  await mkdir(join(dir, "crls"), { recursive: true });

  const ccadb: ReportSource[] = [];

  for (const report of ccadbReports(now)) {
    options.log(`fetching ${report.name}`);
    const target = join(dir, report.file);
    await mkdir(dirname(target), { recursive: true });

    const result = await download(report.url, dirname(target), {
      timeoutMs: 10 * 60_000,
      attempts: 4,
    });

    await rename(result.path, target);
    ccadb.push({ ...report, sha256: result.sha256, size: result.size });
  }

  const { records } = await loadCcadb(dir, ccadb);
  const today = now.toISOString().slice(0, 10);
  const sources = new Map<string, CrlSource>();

  for (const record of records.values()) {
    // every unexpired CA, trusted or not: revoked CAs' CRLs still matter, and
    // the dataset is not tied to one root store
    if (record.validTo && record.validTo < today) continue;

    const add = (url: string, partitioned: boolean) => {
      const source = sources.getOrInsertComputed(url, () => ({ url, issuers: [], partitioned }));
      source.issuers.push(record.fingerprint);
      source.partitioned ||= partitioned;
    };

    record.fullCrls.forEach((url) => add(url, false));
    record.partitionedCrls.forEach((url) => add(url, true));
  }

  const crls = [...sources.values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  crls.forEach((source) => source.issuers.sort());
  options.log(`fetching ${crls.length} CRLs`);

  const global = new Semaphore(options.concurrency);
  const hosts = new Map<string, Semaphore>();
  let done = 0;
  let failed = 0;
  await Promise.all(
    crls.map(async (source) => {
      let host: string;

      try {
        host = new URL(source.url).host;
      } catch {
        source.error = "invalid URL";
        failed++;

        return;
      }

      const hostLimit = hosts.getOrInsertComputed(host, () => new Semaphore(options.perHost));
      await hostLimit.run(() =>
        global.run(async () => {
          source.fetchedAt = new Date().toISOString();

          try {
            // CRLs are signed, so a plain HTTP copy is as good as an HTTPS one
            const result = await download(source.url, join(dir, "crls"), {
              suffix: ".crl",
              httpFallback: true,
            });

            source.status = result.status;

            if (result.finalUrl !== source.url) source.finalUrl = result.finalUrl;
            source.sha256 = result.sha256;
            source.size = result.size;
            source.attempts = result.attempts;
          } catch (error) {
            source.error = errorMessage(error);
            failed++;
          }

          if (++done % 500 === 0) options.log(`  ${done}/${crls.length} (${failed} failed)`);
        }),
      );
    }),
  );
  options.log(`fetched ${crls.length - failed}/${crls.length} CRLs`);

  const manifest: Manifest = {
    format: 1,
    snapshotTime: now.toISOString(),
    tool: { commit: toolCommit(), node: process.version },
    ccadb,
    crls,
  };

  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest, null, 1) + "\n");

  return manifest;
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const detail = error.cause instanceof Error ? `: ${error.cause.message}` : "";

    return `${error.name === "Error" ? "" : `${error.name}: `}${error.message}${detail}`;
  }

  return String(error);
}
