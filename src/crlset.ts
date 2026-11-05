// Chromium CRLSet format, see net/cert/crl_set.cc:
//
//   uint16le header_len
//   byte[header_len] JSON header
//   repeated {
//     byte[32] SHA-256 of the issuer's SubjectPublicKeyInfo
//     uint32le num_serials
//     num_serials x { uint8 len; byte[len] serial }
//   }

import { open } from "node:fs/promises";

export const MAX_HEADER_LENGTH = 0xffff;
export const MAX_SERIALS_PER_PARENT = 32 * 1024 * 1024;

export interface CrlSetHeader {
  Sequence: number;
  NotAfter?: number;
  BlockedSPKIs?: string[];
  KnownInterceptionSPKIs?: string[];
  BlockedInterceptionSPKIs?: string[];
  LimitedSubjects?: Record<string, string[]>;
}

export interface CrlSet {
  // the fields Chromium reads, as it reads them
  header: CrlSetHeader;
  // the header as written
  json: string;
  // parent SPKI SHA-256 (hex) -> serials (hex)
  parents: Map<string, string[]>;
}

// The header as written, in a fixed key order so the output is deterministic.
interface EncodedHeader extends CrlSetHeader {
  Version: 0;
  ContentType: "CRLSet";
  NumParents: number;
  BlockedSPKIs: string[];
}

export function encodeHeader(header: CrlSetHeader, numParents: number): Buffer {
  if (!Number.isInteger(header.Sequence) || header.Sequence < 1 || header.Sequence > 0x7fffffff) {
    throw new Error(`Sequence must be an int32 >= 1, got ${header.Sequence}`);
  }

  const ordered: EncodedHeader = {
    Version: 0,
    ContentType: "CRLSet",
    Sequence: header.Sequence,
    NumParents: numParents,
    BlockedSPKIs: header.BlockedSPKIs ?? [],
  };

  if (header.NotAfter !== undefined) ordered.NotAfter = header.NotAfter;

  if (header.KnownInterceptionSPKIs?.length)
    ordered.KnownInterceptionSPKIs = header.KnownInterceptionSPKIs;

  if (header.BlockedInterceptionSPKIs?.length)
    ordered.BlockedInterceptionSPKIs = header.BlockedInterceptionSPKIs;

  if (header.LimitedSubjects && Object.keys(header.LimitedSubjects).length) {
    ordered.LimitedSubjects = header.LimitedSubjects;
  }

  const json = Buffer.from(JSON.stringify(ordered), "utf8");

  if (json.length > MAX_HEADER_LENGTH) {
    throw new Error(`CRLSet header is ${json.length} bytes, limit is ${MAX_HEADER_LENGTH}`);
  }

  const prefix = Buffer.alloc(2);
  prefix.writeUInt16LE(json.length);

  return Buffer.concat([prefix, json]);
}

export function encodeParent(spkiSha256: string, serials: string[]): Buffer {
  const hash = Buffer.from(spkiSha256, "hex");

  if (hash.length !== 32) {
    throw new Error(`bad parent hash ${spkiSha256}`);
  }

  if (serials.length > MAX_SERIALS_PER_PARENT) {
    throw new Error(`too many serials for ${spkiSha256}`);
  }

  const parts: Buffer[] = [hash, Buffer.alloc(4)];
  parts[1]!.writeUInt32LE(serials.length);

  for (const hex of serials) {
    const serial = Buffer.from(hex, "hex");

    if (serial.length === 0 || serial.length > 255) {
      throw new Error(`bad serial length for ${hex}`);
    }

    parts.push(Buffer.of(serial.length), serial);
  }

  return Buffer.concat(parts);
}

// Parents are written in the iteration order of the map; callers sort them.
export function encodeCrlSet(header: CrlSetHeader, parents: Map<string, string[]>): Buffer {
  const parts = [encodeHeader(header, parents.size)];

  for (const [hash, serials] of parents) {
    parts.push(encodeParent(hash, serials));
  }

  return Buffer.concat(parts);
}

// Streams parents to disk, for tiers too large to keep in memory. Parents are
// written in the order they are added; callers sort them.
export class CrlSetWriter {
  #bodyPath: string;
  #body: Awaited<ReturnType<typeof open>> | undefined;
  #parents = 0;

  constructor(bodyPath: string) {
    this.#bodyPath = bodyPath;
  }

  async add(spkiSha256: string, serials: string[]) {
    if (serials.length === 0) return;
    this.#body ??= await open(this.#bodyPath, "w");
    await this.#body.write(encodeParent(spkiSha256, serials));
    this.#parents++;
  }

  async finish(header: CrlSetHeader, outPath: string) {
    await this.#body?.close();
    const out = await open(outPath, "w");

    try {
      await out.write(encodeHeader(header, this.#parents));

      if (this.#body) {
        const body = await open(this.#bodyPath, "r");

        try {
          for await (const chunk of body.readableWebStream()) {
            await out.write(chunk);
          }
        } finally {
          await body.close();
        }
      }
    } finally {
      await out.close();
    }
  }
}

// base::Base64Decode with the default (strict) policy.
const STRICT_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function hashList(header: Map<string, unknown>, key: string): string[] | undefined {
  const value = header.get(key);

  // FindList returns nothing for non-lists, which is not an error.
  if (!Array.isArray(value)) return undefined;

  return value.map((item) => {
    if (typeof item !== "string" || !STRICT_BASE64.test(item)) {
      throw new Error(`${key}: bad base64 entry`);
    }

    return item;
  });
}

// A strict port of CRLSet::Parse, so generated files are checked against the
// same rules Chromium applies.
export function parseCrlSet(data: Buffer): CrlSet {
  if (data.length < 2) throw new Error("missing header length");
  const headerLength = data.readUInt16LE(0);

  if (data.length < 2 + headerLength) throw new Error("truncated header");

  let header: unknown;

  try {
    header = JSON.parse(data.subarray(2, 2 + headerLength).toString("utf8"));
  } catch {
    throw new Error("header is not valid JSON");
  }

  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    throw new Error("header is not a dictionary");
  }

  const dict = new Map(Object.entries(header));

  if (dict.get("ContentType") !== "CRLSet") throw new Error("ContentType is not CRLSet");

  if (dict.get("Version") !== 0) throw new Error("unsupported Version");
  const sequence = dict.get("Sequence");

  if (
    typeof sequence !== "number" ||
    !Number.isInteger(sequence) ||
    sequence < -0x80000000 ||
    sequence > 0x7fffffff
  ) {
    throw new Error("Sequence is not an int32");
  }

  const notAfter = dict.get("NotAfter");

  if (typeof notAfter === "number" && notAfter < 0) throw new Error("negative NotAfter");

  const parents = new Map<string, string[]>();
  let offset = 2 + headerLength;

  while (offset < data.length) {
    if (offset + 36 > data.length) throw new Error("truncated parent record");
    const hash = data.subarray(offset, offset + 32).toString("hex");
    const count = data.readUInt32LE(offset + 32);
    offset += 36;

    if (count > MAX_SERIALS_PER_PARENT) throw new Error("too many serials");
    const serials: string[] = [];

    for (let i = 0; i < count; i++) {
      if (offset >= data.length) throw new Error("truncated serial");
      const length = data[offset]!;

      if (offset + 1 + length > data.length) throw new Error("truncated serial");
      serials.push(data.subarray(offset + 1, offset + 1 + length).toString("hex"));
      offset += 1 + length;
    }

    parents.set(hash, serials);
  }

  const limited = dict.get("LimitedSubjects");
  let limitedSubjects: Record<string, string[]> | undefined;

  if (
    limited !== undefined &&
    typeof limited === "object" &&
    limited !== null &&
    !Array.isArray(limited)
  ) {
    limitedSubjects = {};

    for (const [subject, spkis] of Object.entries(limited)) {
      if (!Array.isArray(spkis)) throw new Error("LimitedSubjects: value is not a list");

      if (!STRICT_BASE64.test(subject)) throw new Error("LimitedSubjects: bad base64 key");

      limitedSubjects[subject] = spkis.map((spki) => {
        if (typeof spki !== "string" || !STRICT_BASE64.test(spki)) {
          throw new Error("LimitedSubjects: bad base64 entry");
        }

        return spki;
      });
    }
  }

  return {
    header: {
      Sequence: sequence,
      NotAfter: typeof notAfter === "number" ? notAfter : undefined,
      BlockedSPKIs: hashList(dict, "BlockedSPKIs"),
      KnownInterceptionSPKIs: hashList(dict, "KnownInterceptionSPKIs"),
      BlockedInterceptionSPKIs: hashList(dict, "BlockedInterceptionSPKIs"),
      LimitedSubjects: limitedSubjects,
    },
    json: data.subarray(2, 2 + headerLength).toString("utf8"),
    parents,
  };
}

// Mirrors CRLSet::CheckSerial for a single parent.
export function checkSerial(
  set: CrlSet,
  issuerSpkiSha256: string,
  serial: Buffer,
): "revoked" | "good" | "unknown" {
  if (serial.length > 0 && serial[0]! & 0x80) return "unknown";
  let start = 0;

  while (start < serial.length - 1 && serial[start] === 0) start++;
  const serials = set.parents.get(issuerSpkiSha256);

  if (!serials) return "unknown";

  return serials.includes(serial.subarray(start).toString("hex")) ? "revoked" : "good";
}
