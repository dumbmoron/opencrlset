// The explorer data the build writes to <out>/explorer and the site reads. No
// Node APIs: the site imports this too, so both sides share one definition.

import type { Overrides, Policy, Tier } from "./policy.ts";

export const SHARD_HEX_DIGITS = 3;

// Per-revocation flags. Tier flags are only set for issuers in the store's scope.
export const FLAG = {
  // a CCADB-disclosed CA certificate
  caDisclosed: 1,
  // revoked by a root key, so a CA certificate
  caByRoot: 2,
  standard: 4,
  priority: 8,
  all: 16,
  // in the official CRLSet compared against
  google: 32,
  // only in the official CRLSet: no CRL we fetched lists it
  googleOnly: 64,
  // in the standard tier, but not in the previous build's
  added: 128,
} as const;

// One line of revocations/<shard>.ndjson.gz: issuer index (or SPKI hash for
// issuers outside CCADB), serial, reason, revocation time, index into the
// issuer's CRL list (-1: none), flags
export type ExplorerRecord = [
  number | string,
  string,
  number | null,
  number | null,
  number,
  number,
];

export type TierCounts = Record<Tier, number>;

export interface CrlStats {
  ok: number;
  failed: number;
  stale: number;
}

// issuers.json: one entry per CA key, in issuer index order
export interface IssuerEntry {
  spki: string;
  name: string;
  owner: string;
  trustedBy: string[];
  inScope: boolean;
  root: boolean;
  revoked: boolean;
  // subject key identifiers and subject name hashes of its certificates, to
  // find the issuer of a pasted certificate
  skis: string[];
  names: string[];
  crls: CrlStats;
  revocations: number;
  tiers: TierCounts;
  google: number;
}

// A key every tier blocks (BlockedSPKIs) because a CA certificate for it was
// revoked for one of POLICY.blockKeyReasons: the first such revocation
export interface BlockedKey {
  spkiSha256: string;
  // the revoking issuer's key, and the revoked certificate's serial there
  issuer: string;
  serial: string;
  reason: number;
}

export interface CrlSourceInfo {
  url: string;
  status: "ok" | "failed" | "not-fetched";
  sha256?: string;
  thisUpdate?: string;
  nextUpdate?: string;
  crlNumber?: string;
  entries?: number;
  warnings: string[];
  error?: string;
}

// issuers/<spki>.json
export interface IssuerDetail {
  spkiSha256: string;
  index: number;
  trustedBy: string[];
  inScope: boolean;
  root: boolean;
  certificates: {
    fingerprint: string;
    name: string;
    owner: string;
    type: "root" | "intermediate";
    parent?: string;
    trustedBy: string[];
    chromeStatus: string;
    revocationStatus: string;
    validTo: string;
    fullCrls: string[];
    partitionedCrls: string[];
  }[];
  // indexed by the records' CRL field
  crls: { sha256: string; sources: CrlSourceInfo[] }[];
  failedCrls: CrlSourceInfo[];
  // CCADB-disclosed CA certificates this key issued
  caCertificates: { serial: string; fingerprint: string; name: string; revocationStatus: string }[];
  revocations: number;
  tiers: TierCounts;
  google: number;
}

export interface GoogleComparison {
  sequence: number;
  notAfter: string | null;
  parents: number;
  serials: number;
  shared: number;
  oursOnly: number;
  googleOnly: {
    // by reason code, "ccadb" or "ca"
    inDatasetWithOtherReason: Record<string, number>;
    issuerKnownButNotInDataset: number;
    unknownIssuer: number;
  };
  unknownIssuers: { spkiSha256: string; serials: number; inCcadb: boolean }[];
  blockedSPKIs: number;
  // of those, keys this build blocks too
  blockedSPKIsShared: number;
  knownInterceptionSPKIs: number;
  blockedInterceptionSPKIs: number;
  perIssuer: {
    spkiSha256: string;
    google: number;
    shared: number;
    oursOnly: number;
    googleOnlyNotInDataset: number;
    googleOnlyOtherReason: number;
  }[];
}

// meta.json: the build report without its large lists, plus what the site
// needs to decode and explain the rest
export interface ExplorerMeta {
  format: number;
  snapshotTime: string;
  snapshotTool: { commit?: string; node: string };
  sequence: number;
  notAfter: string;
  store: string;
  ccadb: { records: number; withCertificate: number; warnings: number };
  crls: {
    disclosed: number;
    fetched: number;
    valid: number;
    failed: number;
    notFetched: number;
    stale: number;
  };
  crlErrors: Record<string, number>;
  dataset: {
    issuers: number;
    revocations: number;
    // by reason code, or "ccadb" for CAs only CCADB marks revoked
    byReason: Record<string, number>;
    skipped: { negativeSerial: number; certificateIssuerEntry: number };
    sha256Uncompressed: string;
  };
  tiers: Record<Tier, { parents: number; serials: number; bytes: number; sha256: string }>;
  blockedKeys: BlockedKey[];
  google?: Omit<GoogleComparison, "perIssuer" | "unknownIssuers">;
  shardHexDigits: number;
  flags: typeof FLAG;
  policy: Policy;
  overrides: Overrides;
  previous: { sequence: number } | null;
}
