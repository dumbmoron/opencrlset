// Minimal zero-copy DER reader, just enough for certificates and (very large) CRLs.

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  ENUMERATED: 0x0a,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export const contextConstructed = (n: number) => 0xa0 | n;
export const contextPrimitive = (n: number) => 0x80 | n;

export interface Element {
  tag: number;
  // the whole TLV
  raw: Buffer;
  // just the contents
  value: Buffer;
}

export class DerError extends Error {}

export class Reader {
  buf: Buffer;
  pos: number;
  end: number;

  constructor(buf: Buffer, start = 0, end = buf.length) {
    this.buf = buf;
    this.pos = start;
    this.end = end;
  }

  static of(element: Element): Reader {
    return new Reader(element.value);
  }

  get done(): boolean {
    return this.pos >= this.end;
  }

  peekTag(): number | undefined {
    return this.done ? undefined : this.buf[this.pos];
  }

  next(): Element {
    const { buf, end } = this;
    const start = this.pos;

    if (start + 2 > end) {
      throw new DerError("truncated element");
    }

    const tag = buf[start]!;

    if ((tag & 0x1f) === 0x1f) {
      throw new DerError("high tag numbers are not supported");
    }

    let length = buf[start + 1]!;
    let offset = start + 2;

    if (length & 0x80) {
      const count = length & 0x7f;

      if (count === 0 || count > 4) {
        throw new DerError(`unsupported length encoding (${count} bytes)`);
      }

      if (offset + count > end) {
        throw new DerError("truncated length");
      }

      length = buf.readUIntBE(offset, count);
      offset += count;
    }

    const valueEnd = offset + length;

    if (valueEnd > end) {
      throw new DerError("element overruns its container");
    }

    this.pos = valueEnd;

    return {
      tag,
      raw: buf.subarray(start, valueEnd),
      value: buf.subarray(offset, valueEnd),
    };
  }

  expect(tag: number): Element {
    const element = this.next();

    if (element.tag !== tag) {
      throw new DerError(`expected tag 0x${tag.toString(16)}, got 0x${element.tag.toString(16)}`);
    }

    return element;
  }

  optional(tag: number): Element | undefined {
    return this.peekTag() === tag ? this.next() : undefined;
  }

  finish() {
    if (!this.done) {
      throw new DerError("unexpected trailing data");
    }
  }
}

export function decodeOid(value: Buffer): string {
  if (value.length === 0) {
    throw new DerError("empty OID");
  }

  const parts: number[] = [];
  let current = 0;

  for (const byte of value) {
    current = current * 128 + (byte & 0x7f);

    if (!(byte & 0x80)) {
      parts.push(current);
      current = 0;
    }
  }

  const first = parts.shift()!;
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];

  return [...head, ...parts].join(".");
}

// Returns seconds since the Unix epoch.
export function decodeTime(element: Element): number {
  const text = element.value.toString("latin1");
  let match: RegExpMatchArray | null;
  let year: number;

  if (element.tag === TAG.UTC_TIME) {
    match = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);

    if (!match) {
      throw new DerError(`bad UTCTime: ${text}`);
    }

    const yy = Number(match[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  } else if (element.tag === TAG.GENERALIZED_TIME) {
    match = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/);

    if (!match) {
      throw new DerError(`bad GeneralizedTime: ${text}`);
    }

    year = Number(match[1]);
  } else {
    throw new DerError(`expected a time, got tag 0x${element.tag.toString(16)}`);
  }

  const [, , month, day, hour, minute, second] = match;

  return (
    Date.UTC(
      year,
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second ?? 0),
    ) / 1000
  );
}

export function isTime(tag: number | undefined): boolean {
  return tag === TAG.UTC_TIME || tag === TAG.GENERALIZED_TIME;
}

export function bitStringBytes(element: Element): Buffer {
  if (element.tag !== TAG.BIT_STRING || element.value.length === 0) {
    throw new DerError("bad BIT STRING");
  }

  return element.value.subarray(1);
}

export function decodeSmallInteger(value: Buffer): number {
  if (value.length === 0 || value.length > 6) {
    throw new DerError("integer out of range");
  }

  return value.readIntBE(0, value.length);
}

// Canonical serial form shared by CRLSets and the dataset: the INTEGER contents
// with redundant leading zero bytes removed, as in CRLSet::CheckSerial.
export function canonicalSerial(value: Buffer): Buffer {
  let start = 0;

  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }

  return value.subarray(start);
}

export function isNegativeSerial(value: Buffer): boolean {
  return value.length > 0 && (value[0]! & 0x80) !== 0;
}

export interface Extension {
  oid: string;
  critical: boolean;
  value: Buffer;
}

// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
export function parseExtensions(element: Element): Extension[] {
  const out: Extension[] = [];
  const reader = Reader.of(element);

  while (!reader.done) {
    const ext = Reader.of(reader.expect(TAG.SEQUENCE));
    const oid = decodeOid(ext.expect(TAG.OID).value);
    const criticalEl = ext.optional(TAG.BOOLEAN);
    const critical = criticalEl !== undefined && criticalEl.value[0] !== 0;
    const value = ext.expect(TAG.OCTET_STRING).value;
    out.push({ oid, critical, value });
  }

  return out;
}

// GeneralNames ::= SEQUENCE OF GeneralName; returns uniformResourceIdentifier entries.
export function generalNameUris(reader: Reader): string[] {
  const uris: string[] = [];

  while (!reader.done) {
    const name = reader.next();

    if (name.tag === contextPrimitive(6)) {
      uris.push(name.value.toString("latin1"));
    }
  }

  return uris;
}
