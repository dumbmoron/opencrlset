import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { once } from "node:events";
import { constants as zlibConstants, createZstdCompress } from "node:zlib";
import { inScope, loadCcadb, type CaRecord, type Store } from "./ccadb.ts";
import { REASON, crlEntries, parseCrl, verifyCrl, type Crl } from "./crl.ts";
import { CrlSetWriter, parseCrlSet, type CrlSet, type CrlSetHeader } from "./crlset.ts";
import { canonicalSerial, isNegativeSerial } from "./der.ts";
import { crlPath, errorMessage, readManifest, reportsOf, type CrlSource } from "./snapshot.ts";
import { loadOverrides, overridesHeader } from "./overrides.ts";
import { POLICY, TIERS, tierVerdict, type Tier } from "./policy.ts";
import {
  ExplorerWriter,
  FLAG,
  SHARD_HEX_DIGITS,
  nameHash,
  subjectKeyId,
  type BlockedKey,
  type CrlSourceInfo,
  type ExplorerMeta,
  type GoogleComparison,
  type IssuerEntry,
  type TierCounts,
} from "./explorer.ts";
import { publicKeyOf, sha256Hex, type Certificate } from "./x509.ts";

const FUTURE_GRACE = 3600;
const CRLSET_LIFETIME = 7 * 86400;

export interface BuildOptions {
  // official CRLSet to compare the standard tier against
  google?: string;
  overrides?: string;
  // trust store whose issuers go into the CRLSet tiers
  store?: Store;
  // the previous build's standard CRLSet, to explain what changed
  previous?: string;
  // write <out>/explorer for the static site
  explorer?: boolean;
  log: (message: string) => void;
}

type CertifiedRecord = CaRecord & { certificate: Certificate };

const certified = (record: CaRecord): record is CertifiedRecord => record.certificate !== undefined;

interface Issuer {
  spki: string;
  records: CertifiedRecord[];
  trustedBy: Set<Store>;
  // validated CRLs: content hash -> thisUpdate
  crls: Map<string, number>;
  stats: { ok: number; failed: number; stale: number };
}

interface SourceResult {
  url: string;
  sha256?: string;
  issuer?: string;
  status: "ok" | "failed" | "not-fetched";
  error?: string;
  warnings: string[];
  thisUpdate?: string;
  nextUpdate?: string;
  crlNumber?: string;
  entries?: number;
}

// one line of revocations.ndjson.zst
interface DatasetRecord {
  issuer: string;
  serial: string;
  reason: number | null;
  revoked: string | null;
  ca: boolean;
  crl: string | null;
}

interface Revocation {
  reason: number | null;
  date: number;
  thisUpdate: number;
  crl: string | null;
}

// one entry of issuers.json
interface IssuerSummary {
  spkiSha256: string;
  trustedBy: Store[];
  certificates: Pick<
    CaRecord,
    "fingerprint" | "name" | "owner" | "type" | "chromeStatus" | "revocationStatus"
  >[];
  crls: Issuer["stats"];
  revocations: number;
  tiers: TierCounts;
}

const iso = (seconds: number) => new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
const byKey = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const bump = (counts: Record<string, number>, key: string) =>
  (counts[key] = (counts[key] ?? 0) + 1);

// the issuer file already says whose CRL it is
const sourceInfo = ({ issuer: _, ...info }: SourceResult): CrlSourceInfo => info;

// Writes newline-delimited JSON through zstd, hashing the uncompressed bytes.
class NdjsonWriter<T> {
  #stream = createZstdCompress({ params: { [zlibConstants.ZSTD_c_compressionLevel]: 12 } });
  #file;
  #hash = createHash("sha256");
  #buffer: string[] = [];
  lines = 0;

  constructor(path: string) {
    this.#file = createWriteStream(path);
    this.#stream.pipe(this.#file);
  }

  async write(value: T) {
    this.#buffer.push(JSON.stringify(value) + "\n");
    this.lines++;

    if (this.#buffer.length >= 4096) await this.#flush();
  }

  async #flush() {
    const chunk = Buffer.from(this.#buffer.join(""), "utf8");
    this.#buffer = [];
    this.#hash.update(chunk);

    if (!this.#stream.write(chunk)) await once(this.#stream, "drain");
  }

  async close(): Promise<string> {
    await this.#flush();
    this.#stream.end();
    await once(this.#file, "close");

    return this.#hash.digest("hex");
  }
}

export async function build(snapshotDir: string, outDir: string, options: BuildOptions) {
  const store = options.store ?? "chrome";
  const manifest = await readManifest(snapshotDir);
  const snapshotTime = Date.parse(manifest.snapshotTime) / 1000;
  const sequence = Math.floor(snapshotTime / 60);
  const notAfter = snapshotTime + CRLSET_LIFETIME;
  const log = options.log;

  log("loading CCADB");
  const ccadb = await loadCcadb(snapshotDir, reportsOf(manifest));

  // Group CA certificates by key: CRLSets (and the dataset) are keyed by the
  // issuer's SPKI hash, which cross-signs and re-issuances share.
  const certifiedRecords = [...ccadb.records.values()].filter(certified);
  const issuers = new Map<string, Issuer>();
  const bySubject = new Map<string, Set<string>>();

  for (const record of certifiedRecords) {
    const { spkiSha256, subject } = record.certificate;

    const issuer = issuers.getOrInsertComputed(spkiSha256, () => ({
      spki: spkiSha256,
      records: [],
      trustedBy: new Set<Store>(),
      crls: new Map(),
      stats: { ok: 0, failed: 0, stale: 0 },
    }));

    issuer.records.push(record);
    record.trustedBy.forEach((s) => issuer.trustedBy.add(s));
    bySubject.getOrInsertComputed(subject.toString("hex"), () => new Set()).add(spkiSha256);
  }

  // CA certificates by (issuer key, serial): entries matching these are
  // revoked CA certificates, which every tier includes.
  const caCertificates = new Map<string, Map<string, CertifiedRecord>>();

  for (const record of certifiedRecords) {
    const parent = record.parent ? ccadb.records.get(record.parent) : undefined;

    if (record.type !== "intermediate" || !parent?.certificate) continue;
    caCertificates
      .getOrInsertComputed(parent.certificate.spkiSha256, () => new Map())
      .set(canonicalSerial(record.certificate.serial).toString("hex"), record);
  }

  log(`validating ${manifest.crls.length} CRLs`);
  const sources: SourceResult[] = [];
  // per issuer key: validated sources, and failed ones its certificates disclose
  const validSources = new Map<string, SourceResult[]>();
  const failedSources = new Map<string, SourceResult[]>();

  for (const source of manifest.crls) {
    const result = await validateSource(
      snapshotDir,
      source,
      ccadb.records,
      issuers,
      bySubject,
      snapshotTime,
    );

    sources.push(result);

    if (result.status === "ok") {
      validSources.getOrInsertComputed(result.issuer!, () => []).push(result);
    } else {
      const disclosers = new Set<string>();

      for (const fp of source.issuers) {
        const spki = ccadb.records.get(fp)?.certificate?.spkiSha256;

        if (spki) disclosers.add(spki);
      }

      for (const spki of disclosers) {
        issuers.get(spki)!.stats.failed++;
        failedSources.getOrInsertComputed(spki, () => []).push(result);
      }
    }
  }

  log("merging revocations");
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  const overrides = await loadOverrides(options.overrides);
  // keys of CA certificates revoked for POLICY.blockKeyReasons, with the first such revocation
  const blockedKeys = new Map<string, BlockedKey>();

  const google = options.google ? parseCrlSet(await readFile(options.google)) : undefined;
  const comparison = google ? new Comparison(google) : undefined;

  const googleSets = new Map(
    [...(google?.parents ?? [])].map(([spki, serials]) => [spki, new Set(serials)]),
  );

  const previous = options.previous ? parseCrlSet(await readFile(options.previous)) : undefined;

  const previousSets = new Map(
    [...(previous?.parents ?? [])].map(([spki, serials]) => [spki, new Set(serials)]),
  );

  const removed: { issuer: string; serial: string; why: string }[] = [];
  let added = 0;

  const explorer =
    options.explorer === false ? undefined : new ExplorerWriter(join(outDir, "explorer"));

  await explorer?.init();
  const explorerIssuers: IssuerEntry[] = [];

  const dataset = new NdjsonWriter<DatasetRecord>(join(outDir, "revocations.ndjson.zst"));

  for (const tier of TIERS) await mkdir(join(outDir, "crlset", tier), { recursive: true });
  const tierWriter = (tier: Tier) => new CrlSetWriter(join(outDir, "crlset", tier, ".body"));

  // parents are added in sorted key order, as Chromium expects
  const tierWriters: Record<Tier, CrlSetWriter> = {
    standard: tierWriter("standard"),
    priority: tierWriter("priority"),
    all: tierWriter("all"),
  };

  const byReason: Record<string, number> = {};
  let skippedNegative = 0;
  let skippedIndirect = 0;
  const issuerSummaries: IssuerSummary[] = [];
  // issuer keys with data in this build
  const processed = new Set<string>();

  for (const spki of [...issuers.keys()].sort(byKey)) {
    const issuer = issuers.get(spki)!;
    const revocations = new Map<string, Revocation>();

    for (const [sha, thisUpdate] of [...issuer.crls].sort(([a], [b]) => byKey(a, b))) {
      const crl = parseCrl(await readFile(crlPath(snapshotDir, sha)));

      for (const entry of crlEntries(crl)) {
        if (entry.hasCertificateIssuer) {
          skippedIndirect++;
          continue;
        }

        if (isNegativeSerial(entry.serial)) {
          skippedNegative++;
          continue;
        }

        if (entry.reason === REASON.removeFromCRL) continue;
        const serial = canonicalSerial(entry.serial).toString("hex");
        const existing = revocations.get(serial);

        // the most recent statement from the CA wins
        if (!existing || thisUpdate > existing.thisUpdate) {
          revocations.set(serial, {
            reason: entry.reason,
            date: entry.revocationDate,
            thisUpdate,
            crl: sha,
          });
        }
      }
    }

    // CA certificates CCADB lists as revoked, even if no CRL we have says so
    for (const [serial, record] of caCertificates.get(spki) ?? []) {
      if (record.revocationStatus === "Revoked" && !revocations.has(serial)) {
        revocations.set(serial, { reason: null, date: 0, thisUpdate: 0, crl: null });
      }
    }

    if (issuer.trustedBy.size === 0 && revocations.size === 0 && !googleSets.has(spki)) continue;
    processed.add(spki);

    const issuerIndex = issuerSummaries.length;
    const inStore = issuer.records.some((r) => inScope(r, store, ccadb.records));
    // roots may only issue CA certificates, so everything a root key revokes is one
    const rootKey = issuer.records.some((r) => r.type === "root");
    const isCa = (serial: string) => rootKey || (caCertificates.get(spki)?.has(serial) ?? false);
    const crlShas = [...issuer.crls.keys()].sort(byKey);
    const crlIndex = new Map(crlShas.map((sha, i) => [sha, i]));
    const theirs = googleSets.get(spki);
    const before = previousSets.get(spki);
    const tiers: Record<Tier, string[]> = { standard: [], priority: [], all: [] };

    for (const serial of [...revocations.keys()].sort(byKey)) {
      const revocation = revocations.get(serial)!;
      const ca = isCa(serial);
      bump(byReason, String(revocation.reason ?? "ccadb"));
      await dataset.write({
        issuer: spki,
        serial,
        reason: revocation.reason,
        revoked: revocation.date ? iso(revocation.date) : null,
        ca,
        crl: revocation.crl,
      });
      let flags = 0;

      if (caCertificates.get(spki)?.has(serial)) flags |= FLAG.caDisclosed;

      if (rootKey) flags |= FLAG.caByRoot;

      if (theirs?.has(serial)) flags |= FLAG.google;

      // like Google's, every disclosed CA certificate revocation counts, even
      // under issuers the store no longer trusts
      for (const tier of TIERS) {
        if (tierVerdict(tier, revocation, ca, inStore, snapshotTime) === "included") {
          tiers[tier].push(serial);
          flags |= FLAG[tier];
        }
      }

      const caRecord = caCertificates.get(spki)?.get(serial);

      if (
        caRecord &&
        revocation.reason !== null &&
        POLICY.blockKeyReasons.includes(revocation.reason)
      ) {
        const key = caRecord.certificate.spkiSha256;
        // the first such revocation is the one reported
        blockedKeys.getOrInsert(key, {
          spkiSha256: key,
          issuer: spki,
          serial,
          reason: revocation.reason,
        });
      }

      if (previous && flags & FLAG.standard && !before?.has(serial)) {
        flags |= FLAG.added;
        added++;
      }

      await explorer?.record([
        issuerIndex,
        serial,
        revocation.reason,
        revocation.date || null,
        revocation.crl ? crlIndex.get(revocation.crl)! : -1,
        flags,
      ]);
    }

    for (const serial of [...(theirs ?? [])].sort(byKey)) {
      if (!revocations.has(serial))
        await explorer?.record([
          issuerIndex,
          serial,
          null,
          null,
          -1,
          FLAG.google | FLAG.googleOnly,
        ]);
    }

    const standardSet = new Set(tiers.standard);

    for (const serial of [...(before ?? [])].sort(byKey)) {
      if (standardSet.has(serial)) continue;
      const revocation = revocations.get(serial);
      let why: string;

      if (!revocation) {
        why = issuer.stats.failed
          ? "no longer on a fetched CRL (some of this issuer's CRLs failed)"
          : "no longer on any fetched CRL";
      } else {
        const verdict = tierVerdict("standard", revocation, isCa(serial), inStore, snapshotTime);
        why = verdict === "scope" ? "issuer is no longer in scope" : `excluded: ${verdict}`;
      }

      removed.push({ issuer: spki, serial, why });
    }

    for (const tier of TIERS) await tierWriters[tier].add(spki, tiers[tier]);
    comparison?.issuer(spki, revocations, tiers.standard, theirs ?? new Set(), isCa);

    const trustedBy = [...issuer.trustedBy].sort();

    const tierCounts: TierCounts = {
      standard: tiers.standard.length,
      priority: tiers.priority.length,
      all: tiers.all.length,
    };

    const certificates = issuer.records
      .map((r) => ({
        fingerprint: r.fingerprint,
        name: r.name,
        owner: r.owner,
        type: r.type,
        parent: r.parent,
        trustedBy: r.trustedBy,
        chromeStatus: r.chromeStatus,
        revocationStatus: r.revocationStatus,
        validTo: r.validTo,
        fullCrls: r.fullCrls,
        partitionedCrls: r.partitionedCrls,
      }))
      .sort((a, b) => byKey(a.fingerprint, b.fingerprint));

    if (explorer) {
      const valid = validSources.get(spki) ?? [];
      await explorer.issuer(spki, {
        spkiSha256: spki,
        index: issuerIndex,
        trustedBy,
        inScope: inStore,
        root: rootKey,
        certificates,
        // indexed by the records' CRL field
        crls: crlShas.map((sha) => ({
          sha256: sha,
          sources: valid.filter((s) => s.sha256 === sha).map(sourceInfo),
        })),
        failedCrls: (failedSources.get(spki) ?? []).map(sourceInfo),
        caCertificates: [...(caCertificates.get(spki) ?? [])]
          .map(([serial, r]) => ({
            serial,
            fingerprint: r.fingerprint,
            name: r.name,
            revocationStatus: r.revocationStatus,
          }))
          .sort((a, b) => byKey(a.serial, b.serial)),
        revocations: revocations.size,
        tiers: tierCounts,
        google: theirs?.size ?? 0,
      });
      const keyCertificates = issuer.records.map((r) => r.certificate);

      const main = [...issuer.records].sort(
        (a, b) =>
          Number(b.trustedBy.length > 0) - Number(a.trustedBy.length > 0) ||
          byKey(a.fingerprint, b.fingerprint),
      )[0]!;

      explorerIssuers.push({
        spki,
        name: main.name,
        owner: main.owner,
        trustedBy,
        inScope: inStore,
        root: rootKey,
        revoked: issuer.records.every(
          (r) => r.revocationStatus === "Revoked" || r.revocationStatus === "Parent Cert Revoked",
        ),
        skis: [...new Set(keyCertificates.map(subjectKeyId).filter((k) => k !== undefined))].sort(),
        names: [...new Set(keyCertificates.map((c) => nameHash(c.subject)))].sort(),
        crls: issuer.stats,
        revocations: revocations.size,
        tiers: tierCounts,
        google: theirs?.size ?? 0,
      });
    }

    issuerSummaries.push({
      spkiSha256: spki,
      trustedBy,
      certificates: certificates.map(
        ({ fingerprint, name, owner, type, chromeStatus, revocationStatus }) => ({
          fingerprint,
          name,
          owner,
          type,
          chromeStatus,
          revocationStatus,
        }),
      ),
      crls: issuer.stats,
      revocations: revocations.size,
      tiers: tierCounts,
    });
  }

  // official entries under keys we have no data for at all
  for (const spki of [...googleSets.keys()].sort(byKey)) {
    if (processed.has(spki)) continue;

    for (const serial of [...googleSets.get(spki)!].sort(byKey)) {
      await explorer?.record([spki, serial, null, null, -1, FLAG.google | FLAG.googleOnly]);
    }
  }

  for (const spki of [...previousSets.keys()].sort(byKey)) {
    if (processed.has(spki)) continue;

    for (const serial of [...previousSets.get(spki)!].sort(byKey)) {
      removed.push({ issuer: spki, serial, why: "issuer has no data in this build" });
    }
  }

  const datasetSha256 = await dataset.close();

  log("writing CRLSets");

  const header: CrlSetHeader = {
    Sequence: sequence,
    NotAfter: notAfter,
    ...overridesHeader(overrides, [...blockedKeys.keys()]),
  };

  const writeTier = async (tier: Tier) => {
    const dir = join(outDir, "crlset", tier);
    const path = join(dir, "crl-set");
    await tierWriters[tier].finish(header, path);
    await rm(join(dir, ".body"), { force: true });
    // parsed back, so the file is checked against Chromium's rules
    const bytes = await readFile(path);
    const parsed = parseCrlSet(bytes);
    let serials = 0;
    parsed.parents.forEach((list) => (serials += list.length));
    await writeFile(
      join(dir, "manifest.json"),
      JSON.stringify(
        { manifest_version: 2, name: `crl-set-${sequence}.data`, version: String(sequence) },
        null,
        2,
      ) + "\n",
    );

    return { parents: parsed.parents.size, serials, bytes: bytes.length, sha256: sha256Hex(bytes) };
  };

  const tierReports: ExplorerMeta["tiers"] = {
    standard: await writeTier("standard"),
    priority: await writeTier("priority"),
    all: await writeTier("all"),
  };

  const crlStats = {
    disclosed: sources.length,
    fetched: sources.filter((s) => s.status !== "not-fetched").length,
    valid: sources.filter((s) => s.status === "ok").length,
    failed: sources.filter((s) => s.status === "failed").length,
    notFetched: sources.filter((s) => s.status === "not-fetched").length,
    stale: sources.filter((s) => s.warnings.includes("stale")).length,
  };

  const report = {
    format: 1,
    snapshotTime: manifest.snapshotTime,
    snapshotTool: manifest.tool,
    sequence,
    notAfter: iso(notAfter),
    store,
    ccadb: {
      records: ccadb.records.size,
      withCertificate: [...ccadb.records.values()].filter((r) => r.certificate).length,
      warnings: ccadb.warnings.length,
    },
    crls: crlStats,
    crlErrors: tally(
      sources.flatMap((s) => (s.error ? [s.error.replace(/https?:\/\/\S+/g, "<url>")] : [])),
    ),
    dataset: {
      issuers: issuerSummaries.length,
      revocations: dataset.lines,
      byReason,
      skipped: { negativeSerial: skippedNegative, certificateIssuerEntry: skippedIndirect },
      sha256Uncompressed: datasetSha256,
    },
    overrides: {
      BlockedSPKIs: overrides.BlockedSPKIs.length,
      KnownInterceptionSPKIs: overrides.KnownInterceptionSPKIs.length,
      BlockedInterceptionSPKIs: overrides.BlockedInterceptionSPKIs.length,
      LimitedSubjects: overrides.LimitedSubjects.length,
    },
    tiers: tierReports,
    blockedKeys: [...blockedKeys.values()].sort((a, b) => byKey(a.spkiSha256, b.spkiSha256)),
    google: comparison?.finish(issuers, blockedKeys),
    // the standard tier against the previous build's
    changes: previous ? { previous: previous.header.Sequence, added, removed } : undefined,
  };

  if (explorer) {
    await explorer.finish();
    const { google: googleReport, crlErrors, changes: _, ...summary } = report;
    await explorer.json("meta.json", {
      ...summary,
      crlErrors,
      google: googleReport && withoutLists(googleReport),
      shardHexDigits: SHARD_HEX_DIGITS,
      flags: FLAG,
      policy: POLICY,
      overrides,
      previous: previous ? { sequence: previous.header.Sequence } : null,
    } satisfies ExplorerMeta);
    await explorer.json("issuers.json", explorerIssuers);
  }

  await writeJson(join(outDir, "issuers.json"), issuerSummaries);
  await writeJson(join(outDir, "sources.json"), sources);
  await writeJson(join(outDir, "ccadb-warnings.json"), ccadb.warnings);
  await writeJson(join(outDir, "report.json"), report);

  return report;
}

async function writeJson(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value, null, 1) + "\n");
}

function withoutLists({ perIssuer: _, unknownIssuers: __, ...summary }: GoogleComparison) {
  return summary;
}

function tally(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const value of values) bump(counts, value);

  return Object.fromEntries(Object.entries(counts).sort(([a, x], [b, y]) => y - x || byKey(a, b)));
}

async function validateSource(
  snapshotDir: string,
  source: CrlSource,
  records: Map<string, CaRecord>,
  issuers: Map<string, Issuer>,
  bySubject: Map<string, Set<string>>,
  snapshotTime: number,
): Promise<SourceResult> {
  const result: SourceResult = { url: source.url, status: "not-fetched", warnings: [] };

  if (!source.sha256) {
    result.error = source.error ?? "not fetched";

    return result;
  }

  result.sha256 = source.sha256;
  result.status = "failed";

  let crl: Crl;

  try {
    crl = parseCrl(await readFile(crlPath(snapshotDir, source.sha256)));
  } catch (error) {
    result.error = `parse: ${errorMessage(error)}`;

    return result;
  }

  result.thisUpdate = iso(crl.thisUpdate);

  if (crl.nextUpdate !== undefined) result.nextUpdate = iso(crl.nextUpdate);
  result.crlNumber = crl.crlNumber;

  // Prefer the keys of the CCADB records that disclose this URL, then any CA
  // with the CRL's issuer name.
  const disclosed = source.issuers
    .map((fp) => records.get(fp)?.certificate)
    .filter((c) => c !== undefined);

  const candidates = [...new Set(disclosed.map((c) => c.spkiSha256))];

  for (const spki of bySubject.get(crl.issuer.toString("hex")) ?? []) {
    if (!candidates.includes(spki)) candidates.push(spki);
  }

  let signer: string | undefined;

  for (const spki of candidates) {
    const spkiDer = issuers.get(spki)!.records[0]!.certificate.spki;

    try {
      if (verifyCrl(crl, publicKeyOf(spkiDer))) {
        signer = spki;
        break;
      }
    } catch (error) {
      result.error = `signature: ${errorMessage(error)}`;

      return result;
    }
  }

  if (!signer) {
    result.error = candidates.length
      ? "signature does not verify with any matching CA key"
      : "no CA with this issuer name";

    return result;
  }

  result.issuer = signer;

  if (!disclosed.some((c) => c.spkiSha256 === signer))
    result.warnings.push("signed by a CA other than the discloser");

  if (!disclosed.some((c) => c.subject.equals(crl.issuer)))
    result.warnings.push("issuer name differs from discloser");

  if (crl.idp?.onlyContainsAttributeCerts) {
    result.error = "attribute certificate CRL";

    return result;
  }

  if (crl.idp?.indirectCRL) {
    result.error = "indirect CRLs are not supported";

    return result;
  }

  if (crl.isDelta) result.warnings.push("delta CRL");

  if (source.partitioned && !crl.idp?.uris.includes(source.url))
    result.warnings.push("partitioned CRL without matching IDP");

  if (!source.partitioned && crl.idp?.uris.length)
    result.warnings.push("full CRL with distribution point");

  if (crl.nextUpdate !== undefined && crl.nextUpdate < snapshotTime) result.warnings.push("stale");

  if (crl.thisUpdate > snapshotTime + FUTURE_GRACE)
    result.warnings.push("thisUpdate in the future");

  let entries = 0;

  if (crl.revokedCertificates) {
    try {
      entries = crlEntries(crl).reduce((count) => count + 1, 0);
    } catch (error) {
      result.error = `entries: ${errorMessage(error)}`;

      return result;
    }
  }

  result.entries = entries;
  result.status = "ok";

  const issuer = issuers.get(signer)!;
  issuer.crls.set(source.sha256, crl.thisUpdate);
  issuer.stats.ok++;

  if (result.warnings.includes("stale")) issuer.stats.stale++;

  return result;
}

// Compares the standard tier against an official CRLSet, issuer by issuer.
class Comparison {
  google: CrlSet;
  seen = new Set<string>();
  shared = 0;
  oursOnly = 0;
  // Google-only serials we have under another reason, by reason
  otherReason: Record<string, number> = {};
  // Google-only serials under issuers we know, but on no CRL we fetched
  notInDataset = 0;
  perIssuer: {
    spkiSha256: string;
    google: number;
    shared: number;
    oursOnly: number;
    googleOnlyNotInDataset: number;
    googleOnlyOtherReason: number;
  }[] = [];

  constructor(google: CrlSet) {
    this.google = google;
  }

  issuer(
    spki: string,
    revocations: Map<string, Revocation>,
    standard: string[],
    theirs: Set<string>,
    isCa: (serial: string) => boolean,
  ) {
    this.seen.add(spki);
    const ours = new Set(standard);
    let shared = 0;
    let notInDataset = 0;
    let otherReason = 0;

    for (const serial of theirs) {
      if (ours.has(serial)) {
        shared++;
        continue;
      }

      const revocation = revocations.get(serial);

      if (revocation) {
        otherReason++;
        bump(this.otherReason, isCa(serial) ? "ca" : String(revocation.reason ?? "ccadb"));
      } else {
        notInDataset++;
      }
    }

    const oursOnly = standard.length - shared;
    this.shared += shared;
    this.oursOnly += oursOnly;
    this.notInDataset += notInDataset;

    if (theirs.size || oursOnly) {
      this.perIssuer.push({
        spkiSha256: spki,
        google: theirs.size,
        shared,
        oursOnly,
        googleOnlyNotInDataset: notInDataset,
        googleOnlyOtherReason: otherReason,
      });
    }
  }

  finish(issuers: Map<string, Issuer>, blockedKeys: Map<string, BlockedKey>): GoogleComparison {
    const unseen = [...this.google.parents.keys()]
      .filter((spki) => !this.seen.has(spki))
      .sort(byKey);

    let googleSerials = 0;
    this.google.parents.forEach((serials) => (googleSerials += serials.length));

    const unseenSerials = unseen.reduce(
      (sum, spki) => sum + this.google.parents.get(spki)!.length,
      0,
    );

    const header = this.google.header;
    const theirBlocked = header.BlockedSPKIs ?? [];

    return {
      sequence: header.Sequence,
      notAfter: header.NotAfter === undefined ? null : iso(header.NotAfter),
      parents: this.google.parents.size,
      serials: googleSerials,
      shared: this.shared,
      oursOnly: this.oursOnly,
      googleOnly: {
        inDatasetWithOtherReason: this.otherReason,
        issuerKnownButNotInDataset: this.notInDataset,
        unknownIssuer: unseenSerials,
      },
      unknownIssuers: unseen.map((spki) => ({
        spkiSha256: spki,
        serials: this.google.parents.get(spki)!.length,
        inCcadb: issuers.has(spki),
      })),
      blockedSPKIs: theirBlocked.length,
      blockedSPKIsShared: theirBlocked.filter((b) =>
        blockedKeys.has(Buffer.from(b, "base64").toString("hex")),
      ).length,
      knownInterceptionSPKIs: header.KnownInterceptionSPKIs?.length ?? 0,
      blockedInterceptionSPKIs: header.BlockedInterceptionSPKIs?.length ?? 0,
      perIssuer: this.perIssuer.sort(
        (a, b) => b.google - b.shared - (a.google - a.shared) || byKey(a.spkiSha256, b.spkiSha256),
      ),
    };
  }
}
