// Finds a serial's revocation entries and the issuer data that explains them.

import type { ExplorerMeta, IssuerDetail, IssuerEntry } from "opencrlset/explorer-format";
import { parseCertificate, pemToDer, sha256Hex, type PastedCertificate } from "./cert.ts";
import * as data from "./data.ts";
import { canonicalSerial, decodeRecord, type Revocation } from "./explain.ts";

export interface Match {
  record: Revocation;
  // undefined for issuers outside CCADB, which only Google's CRLSet names
  summary?: IssuerEntry;
  detail?: IssuerDetail | null;
}

export interface LookupResult {
  serial: string;
  matches: Match[];
  // for a certificate: the CA keys that could have issued it
  candidates?: IssuerEntry[];
}

export interface Query {
  serial: string;
  certificate?: PastedCertificate;
}

// A hex serial or a PEM certificate.
export function parseQuery(query: string): Query {
  if (query.includes("BEGIN CERTIFICATE")) {
    const der = pemToDer(query);

    if (!der) throw new Error("no PEM certificate found");
    const certificate = parseCertificate(der);

    if (certificate.negativeSerial) throw new Error("negative serial, which CRLSets can't match");

    return { serial: certificate.serial, certificate };
  }

  const serial = canonicalSerial(query);

  if (!serial) throw new Error("not a hex serial or PEM certificate");

  return { serial };
}

export async function lookup(meta: ExplorerMeta, query: string): Promise<LookupResult> {
  const { serial, certificate } = parseQuery(query);
  const [issuers, records] = await Promise.all([data.issuers(), data.lookupSerial(serial)]);
  let found = records.map((line) => decodeRecord(line, meta.flags));

  let candidates: IssuerEntry[] | undefined;

  if (certificate) {
    // the issuer by authority key identifier, or else by name
    const nameHash = (await sha256Hex(certificate.issuer)).slice(0, 16);
    candidates = issuers.filter(
      (i) =>
        (certificate.authorityKeyId && i.skis.includes(certificate.authorityKeyId)) ||
        i.names.includes(nameHash),
    );
    const keys = new Set(candidates.map((i) => i.spki));
    found = found.filter(
      (r) => typeof r.issuer === "number" && keys.has(issuers[r.issuer]?.spki ?? ""),
    );
  }

  const matches = await Promise.all(
    found.map(async (record): Promise<Match> => {
      const summary = typeof record.issuer === "number" ? issuers[record.issuer] : undefined;

      return { record, summary, detail: summary ? await data.issuer(summary.spki) : undefined };
    }),
  );

  return { serial, matches, candidates };
}
