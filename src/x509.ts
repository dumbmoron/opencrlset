import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import {
  Reader,
  TAG,
  contextConstructed,
  decodeOid,
  decodeTime,
  parseExtensions,
  type Element,
  type Extension,
} from "./der.ts";

export interface AlgorithmIdentifier {
  oid: string;
  params?: Element;
}

export interface Certificate {
  raw: Buffer;
  sha256: string;
  serial: Buffer;
  issuer: Buffer;
  subject: Buffer;
  notBefore: number;
  notAfter: number;
  spki: Buffer;
  spkiSha256: string;
  extensions: Extension[];
}

export const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();
export const sha256Hex = (data: Buffer | string) => sha256(data).toString("hex");

export function parseAlgorithm(element: Element): AlgorithmIdentifier {
  const reader = Reader.of(element);
  const oid = decodeOid(reader.expect(TAG.OID).value);
  const params = reader.done ? undefined : reader.next();

  return { oid, params };
}

export function parseCertificate(der: Buffer): Certificate {
  const outer = new Reader(der);
  const certificate = Reader.of(outer.expect(TAG.SEQUENCE));
  outer.finish();

  const tbs = Reader.of(certificate.expect(TAG.SEQUENCE));
  tbs.optional(contextConstructed(0));
  const serial = tbs.expect(TAG.INTEGER).value;
  tbs.expect(TAG.SEQUENCE);
  const issuer = tbs.expect(TAG.SEQUENCE).raw;
  const validity = Reader.of(tbs.expect(TAG.SEQUENCE));
  const notBefore = decodeTime(validity.next());
  const notAfter = decodeTime(validity.next());
  const subject = tbs.expect(TAG.SEQUENCE).raw;
  const spki = tbs.expect(TAG.SEQUENCE).raw;
  tbs.optional(contextConstructed(1));
  tbs.optional(contextConstructed(2));
  const extensionsWrapper = tbs.optional(contextConstructed(3));

  const extensions = extensionsWrapper
    ? parseExtensions(Reader.of(extensionsWrapper).expect(TAG.SEQUENCE))
    : [];

  return {
    raw: der,
    sha256: sha256Hex(der).toUpperCase(),
    serial,
    issuer,
    subject,
    notBefore,
    notAfter,
    spki,
    spkiSha256: sha256Hex(spki),
    extensions,
  };
}

export function pemToDer(pem: string): Buffer[] {
  const out: Buffer[] = [];
  const pattern = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

  for (const match of pem.matchAll(pattern)) {
    out.push(Buffer.from(match[2]!.replace(/\s+/g, ""), "base64"));
  }

  return out;
}

const keyCache = new Map<string, KeyObject>();

export function publicKeyOf(spki: Buffer): KeyObject {
  return keyCache.getOrInsertComputed(sha256Hex(spki), () =>
    createPublicKey({ key: spki, format: "der", type: "spki" }),
  );
}
