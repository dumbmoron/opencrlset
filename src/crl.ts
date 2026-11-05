import { constants, verify, type KeyObject } from "node:crypto";
import {
  DerError,
  Reader,
  TAG,
  bitStringBytes,
  contextConstructed,
  contextPrimitive,
  decodeSmallInteger,
  decodeTime,
  generalNameUris,
  isTime,
  parseExtensions,
  type Element,
} from "./der.ts";
import { REASON } from "./reasons.ts";
import { parseAlgorithm, pemToDer, type AlgorithmIdentifier } from "./x509.ts";

export { REASON };

const OID = {
  crlNumber: "2.5.29.20",
  reasonCode: "2.5.29.21",
  deltaCrlIndicator: "2.5.29.27",
  issuingDistributionPoint: "2.5.29.28",
  certificateIssuer: "2.5.29.29",
} as const;

export interface IssuingDistributionPoint {
  uris: string[];
  onlyContainsUserCerts: boolean;
  onlyContainsCACerts: boolean;
  onlySomeReasons: boolean;
  indirectCRL: boolean;
  onlyContainsAttributeCerts: boolean;
}

export interface Crl {
  tbs: Buffer;
  signatureAlgorithm: AlgorithmIdentifier;
  signature: Buffer;
  issuer: Buffer;
  thisUpdate: number;
  nextUpdate?: number;
  crlNumber?: string;
  isDelta: boolean;
  idp?: IssuingDistributionPoint;
  revokedCertificates?: Element;
}

export interface CrlEntry {
  serial: Buffer;
  revocationDate: number;
  reason: number;
  hasCertificateIssuer: boolean;
}

export function crlDer(bytes: Buffer): Buffer {
  const head = bytes.subarray(0, 64).toString("latin1");

  if (head.includes("-----BEGIN")) {
    const [der] = pemToDer(bytes.toString("latin1"));

    if (!der) {
      throw new DerError("unreadable PEM CRL");
    }

    return der;
  }

  return bytes;
}

function parseIdp(value: Buffer): IssuingDistributionPoint {
  const idp: IssuingDistributionPoint = {
    uris: [],
    onlyContainsUserCerts: false,
    onlyContainsCACerts: false,
    onlySomeReasons: false,
    indirectCRL: false,
    onlyContainsAttributeCerts: false,
  };

  const outer = new Reader(value);
  const reader = Reader.of(outer.expect(TAG.SEQUENCE));
  const flag = (element: Element) => element.value[0] !== 0;

  while (!reader.done) {
    const element = reader.next();

    switch (element.tag) {
      case contextConstructed(0): {
        const name = Reader.of(element).next();

        if (name.tag === contextConstructed(0)) {
          idp.uris.push(...generalNameUris(Reader.of(name)));
        }

        break;
      }

      case contextPrimitive(1):
        idp.onlyContainsUserCerts = flag(element);
        break;
      case contextPrimitive(2):
        idp.onlyContainsCACerts = flag(element);
        break;
      case contextPrimitive(3):
        idp.onlySomeReasons = true;
        break;
      case contextPrimitive(4):
        idp.indirectCRL = flag(element);
        break;
      case contextPrimitive(5):
        idp.onlyContainsAttributeCerts = flag(element);
        break;
    }
  }

  return idp;
}

export function parseCrl(bytes: Buffer): Crl {
  const outer = new Reader(crlDer(bytes));
  const certList = Reader.of(outer.expect(TAG.SEQUENCE));
  outer.finish();

  const tbsElement = certList.expect(TAG.SEQUENCE);
  const signatureAlgorithm = parseAlgorithm(certList.expect(TAG.SEQUENCE));
  const signature = bitStringBytes(certList.expect(TAG.BIT_STRING));

  const tbs = Reader.of(tbsElement);
  tbs.optional(TAG.INTEGER);
  tbs.expect(TAG.SEQUENCE);
  const issuer = tbs.expect(TAG.SEQUENCE).raw;
  const thisUpdate = decodeTime(tbs.next());
  const nextUpdate = isTime(tbs.peekTag()) ? decodeTime(tbs.next()) : undefined;
  const revokedCertificates = tbs.optional(TAG.SEQUENCE);
  const extensionsWrapper = tbs.optional(contextConstructed(0));
  tbs.finish();

  const crl: Crl = {
    tbs: tbsElement.raw,
    signatureAlgorithm,
    signature,
    issuer,
    thisUpdate,
    nextUpdate,
    isDelta: false,
    revokedCertificates,
  };

  if (extensionsWrapper) {
    for (const ext of parseExtensions(Reader.of(extensionsWrapper).expect(TAG.SEQUENCE))) {
      switch (ext.oid) {
        case OID.crlNumber:
          crl.crlNumber = new Reader(ext.value).expect(TAG.INTEGER).value.toString("hex");
          break;
        case OID.deltaCrlIndicator:
          crl.isDelta = true;
          break;
        case OID.issuingDistributionPoint:
          crl.idp = parseIdp(ext.value);
          break;
      }
    }
  }

  return crl;
}

export function* crlEntries(crl: Crl): Generator<CrlEntry> {
  if (!crl.revokedCertificates) {
    return;
  }

  const list = Reader.of(crl.revokedCertificates);

  while (!list.done) {
    const entry = Reader.of(list.expect(TAG.SEQUENCE));
    const serial = entry.expect(TAG.INTEGER).value;
    const revocationDate = decodeTime(entry.next());
    let reason: number = REASON.unspecified;
    let hasCertificateIssuer = false;
    const extensions = entry.optional(TAG.SEQUENCE);

    if (extensions) {
      for (const ext of parseExtensions(extensions)) {
        if (ext.oid === OID.reasonCode) {
          reason = decodeSmallInteger(new Reader(ext.value).expect(TAG.ENUMERATED).value);
        } else if (ext.oid === OID.certificateIssuer) {
          hasCertificateIssuer = true;
        }
      }
    }

    yield { serial, revocationDate, reason, hasCertificateIssuer };
  }
}

// hash algorithm OIDs, as in PSS parameters
const HASHES = new Map([
  ["1.3.14.3.2.26", "sha1"],
  ["2.16.840.1.101.3.4.2.4", "sha224"],
  ["2.16.840.1.101.3.4.2.1", "sha256"],
  ["2.16.840.1.101.3.4.2.2", "sha384"],
  ["2.16.840.1.101.3.4.2.3", "sha512"],
]);

// signature algorithm OIDs and their hash; Ed25519 (null) takes none
const SIGNATURE_HASHES = new Map<string, string | null>([
  ["1.2.840.113549.1.1.5", "sha1"],
  ["1.2.840.113549.1.1.14", "sha224"],
  ["1.2.840.113549.1.1.11", "sha256"],
  ["1.2.840.113549.1.1.12", "sha384"],
  ["1.2.840.113549.1.1.13", "sha512"],
  ["1.2.840.10045.4.1", "sha1"],
  ["1.2.840.10045.4.3.1", "sha224"],
  ["1.2.840.10045.4.3.2", "sha256"],
  ["1.2.840.10045.4.3.3", "sha384"],
  ["1.2.840.10045.4.3.4", "sha512"],
  ["1.3.101.112", null],
]);

const RSA_PSS = "1.2.840.113549.1.1.10";

function pssParameters(params: Element | undefined) {
  let hash = "sha1";
  let saltLength = 20;

  if (params && params.tag === TAG.SEQUENCE) {
    const reader = Reader.of(params);

    while (!reader.done) {
      const element = reader.next();

      if (element.tag === contextConstructed(0)) {
        const oid = parseAlgorithm(Reader.of(element).expect(TAG.SEQUENCE)).oid;
        const name = HASHES.get(oid);

        if (!name) {
          throw new Error(`unsupported PSS hash ${oid}`);
        }

        hash = name;
      } else if (element.tag === contextConstructed(2)) {
        saltLength = decodeSmallInteger(Reader.of(element).expect(TAG.INTEGER).value);
      }
    }
  }

  return { hash, saltLength };
}

export function verifySignature(
  algorithm: AlgorithmIdentifier,
  data: Buffer,
  signature: Buffer,
  key: KeyObject,
): boolean {
  if (algorithm.oid === RSA_PSS) {
    const { hash, saltLength } = pssParameters(algorithm.params);

    return verify(
      hash,
      data,
      { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength },
      signature,
    );
  }

  const hash = SIGNATURE_HASHES.get(algorithm.oid);

  if (hash === undefined) {
    throw new Error(`unsupported signature algorithm ${algorithm.oid}`);
  }

  return verify(hash, data, key, signature);
}

export function verifyCrl(crl: Crl, key: KeyObject): boolean {
  try {
    return verifySignature(crl.signatureAlgorithm, crl.tbs, crl.signature, key);
  } catch (error) {
    // key type and signature algorithm mismatch
    if (
      error instanceof Error &&
      /unsupported signature algorithm|unsupported PSS/.test(error.message)
    ) {
      throw error;
    }

    return false;
  }
}
