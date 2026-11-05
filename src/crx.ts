// CRX3 files, written and checked the way Chromium's components/crx_file does:
//
//   "Cr24" | uint32le 3 | uint32le header_size | CrxFileHeader | zip archive
//
// The header is a protobuf. Each proof signs, with RSA PKCS#1 v1.5 or ECDSA
// over SHA-256: "CRX3 SignedData\0" | uint32le size | SignedData | archive.
// RSA PKCS#1 v1.5 signatures are deterministic, so one key and one archive
// always make the same file.

import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { PbfReader, PbfWriter } from "pbf";
import { sha256 } from "./x509.ts";

const MAGIC = Buffer.from("Cr24", "latin1");
const SIGNATURE_CONTEXT = Buffer.from("CRX3 SignedData\0", "latin1");

// Chromium refuses headers containing these zip end-of-directory markers.
const FORBIDDEN_IN_HEADER = ["PK\x05\x06", "PK\x06\x07", "PK\x06\x06"].map((s) =>
  Buffer.from(s, "latin1"),
);

// CrxFileHeader and SignedData fields (components/crx_file/crx3.proto)
const FIELD = {
  sha256WithRsa: 2,
  sha256WithEcdsa: 3,
  signedHeaderData: 10000,
  publicKey: 1,
  signature: 2,
  crxId: 1,
};

export interface CrxProof {
  publicKey: Buffer;
  signature: Buffer;
  algorithm: "rsa" | "ecdsa";
}

export interface Crx {
  proofs: CrxProof[];
  signedHeaderData: Buffer;
  archive: Buffer;
}

// Extension and component IDs: the first 16 bytes of the SHA-256 of the
// SubjectPublicKeyInfo, in hex with 0-f written as a-p.
export function crxIdFromHash(hash: Buffer): string {
  return [...hash.subarray(0, 16).toString("hex")]
    .map((c) => String.fromCharCode(97 + parseInt(c, 16)))
    .join("");
}

export const crxId = (spki: Buffer) => crxIdFromHash(sha256(spki));

const uint32 = (value: number) => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value);

  return buffer;
};

// A protobuf message of bytes fields. Protobuf writes fields in number order,
// and so must we, for the bytes Chromium would produce.
function message(fields: [number, Buffer][]): Buffer {
  const writer = new PbfWriter();

  for (const [field, value] of fields) writer.writeBytesField(field, value);
  const bytes = writer.finish();

  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

const LENGTH_DELIMITED = 2;

// The bytes fields of a protobuf message, in order; other fields are skipped.
function readFields(bytes: Buffer): { field: number; value: Buffer }[] {
  return new PbfReader(bytes).readFields<{ field: number; value: Buffer }[]>(
    (field, fields, pbf) => {
      if (pbf.type === LENGTH_DELIMITED) {
        const value = pbf.readBytes();
        fields.push({
          field,
          value: Buffer.from(value.buffer, value.byteOffset, value.byteLength),
        });
      }
    },
    [],
  );
}

const signedMessage = (signedHeaderData: Buffer, archive: Buffer) =>
  Buffer.concat([SIGNATURE_CONTEXT, uint32(signedHeaderData.length), signedHeaderData, archive]);

export function packCrx(archive: Buffer, key: KeyObject): Buffer {
  if (key.asymmetricKeyType !== "rsa")
    throw new Error("CRX signing needs an RSA key, for deterministic signatures");
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  const signedHeaderData = message([[FIELD.crxId, sha256(spki).subarray(0, 16)]]);
  const signature = sign("sha256", signedMessage(signedHeaderData, archive), key);

  const proof = message([
    [FIELD.publicKey, spki],
    [FIELD.signature, signature],
  ]);

  const header = message([
    [FIELD.sha256WithRsa, proof],
    [FIELD.signedHeaderData, signedHeaderData],
  ]);

  if (FORBIDDEN_IN_HEADER.some((marker) => header.includes(marker))) {
    // odds are about one in a few million per signature
    throw new Error(
      "CRX header happens to contain a zip end-of-directory marker, which Chromium refuses",
    );
  }

  return Buffer.concat([MAGIC, uint32(3), uint32(header.length), header, archive]);
}

export function parseCrx(bytes: Buffer): Crx {
  if (bytes.length < 12 || !bytes.subarray(0, 4).equals(MAGIC)) throw new Error("not a CRX file");

  if (bytes.readUInt32LE(4) !== 3)
    throw new Error(`unsupported CRX version ${bytes.readUInt32LE(4)}`);
  const headerSize = bytes.readUInt32LE(8);

  if (12 + headerSize > bytes.length) throw new Error("truncated CRX header");
  const header = bytes.subarray(12, 12 + headerSize);

  if (FORBIDDEN_IN_HEADER.some((marker) => header.includes(marker)))
    throw new Error("CRX header contains a zip marker");

  const proofs: CrxProof[] = [];
  let signedHeaderData: Buffer = Buffer.alloc(0);

  for (const { field, value } of readFields(header)) {
    if (field === FIELD.sha256WithRsa || field === FIELD.sha256WithEcdsa) {
      const proof = Object.fromEntries(readFields(value).map((f) => [f.field, f.value]));
      proofs.push({
        publicKey: proof[FIELD.publicKey] ?? Buffer.alloc(0),
        signature: proof[FIELD.signature] ?? Buffer.alloc(0),
        algorithm: field === FIELD.sha256WithRsa ? "rsa" : "ecdsa",
      });
    } else if (field === FIELD.signedHeaderData) {
      signedHeaderData = value;
    }
  }

  return { proofs, signedHeaderData, archive: bytes.subarray(12 + headerSize) };
}

// Mirrors crx_file::Verify: every proof must verify, one key must match the
// declared CRX ID, and each required key hash (a component's
// GetHash(), say) must belong to a proof. Returns the CRX ID and the archive.
export function verifyCrx(
  bytes: Buffer,
  requiredKeyHashes: Buffer[] = [],
): { id: string; archive: Buffer } {
  const crx = parseCrx(bytes);
  const declared = readFields(crx.signedHeaderData).find((f) => f.field === FIELD.crxId)?.value;

  if (!declared) throw new Error("CRX has no declared ID");
  const id = crxIdFromHash(declared);
  const message = signedMessage(crx.signedHeaderData, crx.archive);
  const required = new Set(requiredKeyHashes.map((hash) => hash.toString("hex")));
  let idKeyFound = false;

  for (const proof of crx.proofs) {
    const key = createPublicKey({ key: proof.publicKey, format: "der", type: "spki" });

    if ((proof.algorithm === "rsa") !== (key.asymmetricKeyType === "rsa"))
      throw new Error("CRX proof uses the wrong key type");

    if (!verify("sha256", message, key, proof.signature))
      throw new Error("CRX signature does not verify");

    if (crxId(proof.publicKey) === id) idKeyFound = true;
    required.delete(sha256(proof.publicKey).toString("hex"));
  }

  if (!idKeyFound) throw new Error("no CRX proof matches the declared ID");

  if (required.size) throw new Error("CRX is not signed by the required key");

  return { id, archive: crx.archive };
}
