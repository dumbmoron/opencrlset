// Just enough DER to read a pasted certificate: its serial, issuer name and
// authority key identifier, which identify the revocation entry to look up.

interface Element {
  tag: number;
  offset: number;
  start: number;
  end: number;
}

function readElement(bytes: Uint8Array, offset: number): Element {
  const tag = bytes[offset];
  let length = bytes[offset + 1] ?? 0;
  let start = offset + 2;

  if (length & 0x80) {
    const count = length & 0x7f;

    if (count < 1 || count > 4) throw new Error("unsupported length");
    length = 0;

    for (let i = 0; i < count; i++) length = length * 256 + (bytes[start + i] ?? 0);
    start += count;
  }

  const end = start + length;

  if (tag === undefined || end > bytes.length) throw new Error("truncated certificate");

  return { tag, offset, start, end };
}

function children(bytes: Uint8Array, element: Element): Element[] {
  const out: Element[] = [];

  for (let offset = element.start; offset < element.end;) {
    const child = readElement(bytes, offset);
    out.push(child);
    offset = child.end;
  }

  return out;
}

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

export function pemToDer(text: string): Uint8Array | undefined {
  const match = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);

  if (!match?.[1]) return undefined;
  const binary = atob(match[1].replace(/\s+/g, ""));

  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const AKI_OID = "551d23"; // 2.5.29.35

export interface PastedCertificate {
  // canonical hex, as in the build
  serial: string;
  negativeSerial: boolean;
  issuer: Uint8Array;
  subject: Uint8Array;
  authorityKeyId?: string;
}

export function parseCertificate(der: Uint8Array): PastedCertificate {
  const [tbs] = children(der, readElement(der, 0));

  if (!tbs) throw new Error("empty certificate");
  const fields = children(der, tbs);
  let i = fields[0]?.tag === 0xa0 ? 1 : 0;
  const serialElement = fields[i++];
  i++; // signature algorithm
  const issuer = fields[i++];
  i++; // validity
  const subject = fields[i++];

  if (!serialElement || !issuer || !subject) throw new Error("truncated certificate");

  let authorityKeyId: string | undefined;
  const extensions = fields.find((f) => f.tag === 0xa3);
  const list = extensions && children(der, extensions)[0];

  for (const ext of list ? children(der, list) : []) {
    const parts = children(der, ext);
    const [oid] = parts;
    const value = parts[parts.length - 1];

    if (!oid || !value || hex(der.subarray(oid.start, oid.end)) !== AKI_OID) continue;
    const aki = children(der, value)[0];
    const keyId = aki && children(der, aki).find((p) => p.tag === 0x80);

    if (keyId) authorityKeyId = hex(der.subarray(keyId.start, keyId.end));
  }

  let serial = der.subarray(serialElement.start, serialElement.end);

  while (serial.length > 1 && serial[0] === 0) serial = serial.subarray(1);

  return {
    serial: hex(serial),
    negativeSerial: (der[serialElement.start] ?? 0) >= 0x80,
    issuer: der.subarray(issuer.offset, issuer.end),
    subject: der.subarray(subject.offset, subject.end),
    authorityKeyId,
  };
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);

  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}
