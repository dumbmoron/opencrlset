import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "csv-parse/sync";
import { parseCertificate, pemToDer, type Certificate } from "./x509.ts";

const BASE = "https://ccadb.my.salesforce-sites.com/ccadb";

export const STORES = ["chrome", "mozilla", "apple", "microsoft"] as const;

export type Store = (typeof STORES)[number];

const STATUS_COLUMNS: Record<Store, string> = {
  chrome: "Chrome Status",
  mozilla: "Mozilla Status",
  apple: "Apple Status",
  microsoft: "Microsoft Status",
};

// "Included" is used for roots, "Trusted" for intermediates chaining to one.
const TRUSTED_STATUSES = new Set(["Included", "Trusted"]);

export interface Report {
  name: string;
  url: string;
  file: string;
}

export function ccadbReports(now: Date): Report[] {
  const reports: Report[] = [
    {
      name: "AllCertificateRecordsCSVFormatV5",
      url: `${BASE}/AllCertificateRecordsCSVFormatV5`,
      file: "ccadb/AllCertificateRecordsCSVFormatV5.csv",
    },
  ];

  const lastDecade = Math.floor(now.getUTCFullYear() / 10) * 10;

  for (let decade = 1990; decade <= lastDecade; decade += 10) {
    reports.push({
      name: `AllCertificatePEMsCSVFormat-${decade}`,
      url: `${BASE}/AllCertificatePEMsCSVFormat?NotBeforeDecade=${decade}`,
      file: `ccadb/AllCertificatePEMsCSVFormat-${decade}.csv`,
    });
  }

  return reports;
}

export interface CaRecord {
  fingerprint: string;
  name: string;
  owner: string;
  type: "root" | "intermediate";
  parent?: string;
  revocationStatus: string;
  trustedBy: Store[];
  chromeStatus: string;
  validTo: string;
  fullCrls: string[];
  partitionedCrls: string[];
  certificate?: Certificate;
}

export interface Ccadb {
  records: Map<string, CaRecord>;
  warnings: string[];
}

function urlList(value: string | undefined, warnings: string[], context: string): string[] {
  const text = value?.trim();

  if (!text) return [];
  let items: unknown;

  try {
    items = JSON.parse(text);
  } catch {
    warnings.push(`${context}: unparseable CRL list, extracting URLs`);
    items = text.match(/https?:\/\/[^\s",\]]+/g) ?? [];
  }

  if (!Array.isArray(items)) return [];

  return [
    ...new Set(
      items
        .filter((u): u is string => typeof u === "string" && /^https?:\/\//i.test(u.trim()))
        .map((u) => u.trim()),
    ),
  ].sort();
}

// "2038.01.13" -> "2038-01-13"
const isoDate = (value: string | undefined) => (value ?? "").replaceAll(".", "-");

function readCsv(text: string): Record<string, string>[] {
  return parse(text, { columns: true, bom: true, skip_empty_lines: true, relax_quotes: true });
}

export async function loadCcadb(snapshotDir: string, reports: Report[]): Promise<Ccadb> {
  const warnings: string[] = [];
  const [recordsReport, ...pemReports] = reports;

  const pems = new Map<string, string>();

  for (const report of pemReports) {
    const rows = readCsv(await readFile(join(snapshotDir, report.file), "utf8"));

    for (const row of rows) {
      const fingerprint = row["SHA-256 Fingerprint"]?.toUpperCase();
      const pem = row["X.509 Certificate (PEM)"];

      if (fingerprint && pem) pems.set(fingerprint, pem);
    }
  }

  const records = new Map<string, CaRecord>();
  const rows = readCsv(await readFile(join(snapshotDir, recordsReport!.file), "utf8"));

  for (const row of rows) {
    const fingerprint = row["SHA-256 Fingerprint"]?.toUpperCase();

    if (!fingerprint) continue;
    const context = `${fingerprint} (${row["Certificate Name"]})`;

    const record: CaRecord = {
      fingerprint,
      name: row["Certificate Name"] ?? "",
      owner: row["CA Owner"] ?? "",
      type: row["Certificate Record Type"] === "Root Certificate" ? "root" : "intermediate",
      parent: row["Parent SHA-256 Fingerprint"]?.toUpperCase() || undefined,
      revocationStatus: row["Revocation Status"] ?? "",
      trustedBy: STORES.filter((store) => TRUSTED_STATUSES.has(row[STATUS_COLUMNS[store]] ?? "")),
      chromeStatus: row["Chrome Status"] ?? "",
      validTo: isoDate(row["Valid To (GMT)"]),
      fullCrls: urlList(row["JSON Array of All Full CRL URLs"], warnings, context),
      partitionedCrls: urlList(row["JSON Array of Partitioned CRLs"], warnings, context),
    };

    const pem = pems.get(fingerprint);

    if (!pem) {
      warnings.push(`${context}: no PEM in CCADB`);
    } else {
      try {
        const [der] = pemToDer(pem);
        const certificate = parseCertificate(der!);

        if (certificate.sha256 !== fingerprint) {
          warnings.push(`${context}: PEM does not match fingerprint`);
        } else {
          record.certificate = certificate;
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        warnings.push(`${context}: unparseable certificate: ${message}`);
      }
    }

    records.set(fingerprint, record);
  }

  return { records, warnings };
}

// Whether a store's CRLSet should cover revocations by this CA: the store
// trusts it, or it is revoked (itself or through its parent) and chains to a CA
// the store trusts. The revocation is why the store stopped trusting it, but
// its key may still be certified elsewhere.
export function inScope(record: CaRecord, store: Store, records: Map<string, CaRecord>): boolean {
  if (record.trustedBy.includes(store)) return true;

  if (record.revocationStatus !== "Revoked" && record.revocationStatus !== "Parent Cert Revoked")
    return false;
  let parent = record.parent ? records.get(record.parent) : undefined;

  for (let depth = 0; parent && depth < 10; depth++) {
    if (parent.trustedBy.includes(store)) return true;
    parent = parent.parent ? records.get(parent.parent) : undefined;
  }

  return false;
}
