// Data for the static explorer site (site/): an issuer index, one file per
// issuer with its certificates and CRLs, and every revocation sharded by a
// hash of its serial, so a lookup only fetches one small file.

import { appendFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { constants as zlibConstants, gzipSync } from "node:zlib";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Reader, TAG } from "./der.ts";
import { SHARD_HEX_DIGITS, type ExplorerRecord, type IssuerDetail } from "./explorer-format.ts";
import type { Certificate } from "./x509.ts";

export * from "./explorer-format.ts";

export const shardOf = (serialHex: string) =>
  createHash("sha256").update(serialHex).digest("hex").slice(0, SHARD_HEX_DIGITS);

const SKI_OID = "2.5.29.14";

export function subjectKeyId(certificate: Certificate): string | undefined {
  const ext = certificate.extensions.find((e) => e.oid === SKI_OID);

  if (!ext) return undefined;

  try {
    return new Reader(ext.value).expect(TAG.OCTET_STRING).value.toString("hex");
  } catch {
    return undefined;
  }
}

// a short hash of the DER subject, to match a certificate's issuer name
export const nameHash = (name: Buffer) =>
  createHash("sha256").update(name).digest("hex").slice(0, 16);

export class ExplorerWriter {
  dir: string;
  #shards = new Map<string, string[]>();
  #buffered = 0;
  records = 0;

  constructor(dir: string) {
    this.dir = dir;
  }

  async init() {
    await mkdir(join(this.dir, "revocations"), { recursive: true });
    await mkdir(join(this.dir, "issuers"), { recursive: true });
  }

  async record(record: ExplorerRecord) {
    this.#shards.getOrInsertComputed(shardOf(record[1]), () => []).push(JSON.stringify(record));
    this.records++;

    if (++this.#buffered >= 500_000) await this.#flush();
  }

  async #flush() {
    for (const shard of [...this.#shards.keys()].sort()) {
      await appendFile(
        join(this.dir, "revocations", `${shard}.ndjson`),
        this.#shards.get(shard)!.join("\n") + "\n",
      );
    }

    this.#shards.clear();
    this.#buffered = 0;
  }

  async issuer(spki: string, detail: IssuerDetail) {
    await writeFile(join(this.dir, "issuers", `${spki}.json`), JSON.stringify(detail));
  }

  async json(name: string, data: unknown) {
    await writeFile(join(this.dir, name), JSON.stringify(data));
  }

  // Shards are gzipped (deterministically: node writes no timestamp), which
  // browsers undo with DecompressionStream.
  async finish() {
    await this.#flush();
    const dir = join(this.dir, "revocations");

    for (const name of (await readdir(dir)).sort()) {
      if (!name.endsWith(".ndjson")) continue;
      const path = join(dir, name);
      await writeFile(
        `${path}.gz`,
        gzipSync(await readFile(path), { level: zlibConstants.Z_BEST_COMPRESSION }),
      );
      await rm(path);
    }
  }
}
