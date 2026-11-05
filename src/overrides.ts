// Reviewed additions to the CRLSet header that don't come from CRLs.

import { readFile } from "node:fs/promises";
import type { CrlSetHeader } from "./crlset.ts";
import type { Justified, Overrides } from "./policy.ts";

export type { Overrides };

const HASH = /^[0-9a-f]{64}$/;

function checkHash(value: unknown, context: string): string {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new Error(`${context}: expected a lowercase hex SHA-256`);
  }

  return value;
}

function checkJustified(entry: Justified, context: string) {
  if (!entry.reason?.trim() || !(entry.reference ?? "").startsWith("https://")) {
    throw new Error(`${context}: every override needs a reason and an https reference`);
  }
}

export async function loadOverrides(path: string | undefined): Promise<Overrides> {
  const empty: Overrides = {
    BlockedSPKIs: [],
    KnownInterceptionSPKIs: [],
    BlockedInterceptionSPKIs: [],
    LimitedSubjects: [],
  };

  if (!path) return empty;
  const parsed: Overrides = { ...empty, ...JSON.parse(await readFile(path, "utf8")) };

  for (const key of [
    "BlockedSPKIs",
    "KnownInterceptionSPKIs",
    "BlockedInterceptionSPKIs",
  ] as const) {
    parsed[key].forEach((entry, i) => {
      checkJustified(entry, `${key}[${i}]`);
      checkHash(entry.spkiSha256, `${key}[${i}]`);
    });
  }

  parsed.LimitedSubjects.forEach((entry, i) => {
    checkJustified(entry, `LimitedSubjects[${i}]`);
    checkHash(entry.subjectSha256, `LimitedSubjects[${i}]`);
    entry.allowedSpkiSha256.forEach((hash, j) => checkHash(hash, `LimitedSubjects[${i}][${j}]`));
  });

  return parsed;
}

const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64");
const sortedB64 = (hashes: string[]) => [...new Set(hashes.map(b64))].sort();
const spkis = (entries: { spkiSha256: string }[]) => entries.map((e) => e.spkiSha256);

// blockedKeys: SPKI hashes the build blocks on its own (POLICY.blockKeyReasons)
export function overridesHeader(
  overrides: Overrides,
  blockedKeys: string[],
): Omit<CrlSetHeader, "Sequence"> {
  const limited: Record<string, string[]> = {};

  for (const entry of [...overrides.LimitedSubjects].sort((a, b) =>
    a.subjectSha256 < b.subjectSha256 ? -1 : 1,
  )) {
    limited[b64(entry.subjectSha256)] = [...new Set(entry.allowedSpkiSha256.map(b64))].sort();
  }

  return {
    BlockedSPKIs: sortedB64([...spkis(overrides.BlockedSPKIs), ...blockedKeys]),
    KnownInterceptionSPKIs: sortedB64(spkis(overrides.KnownInterceptionSPKIs)),
    BlockedInterceptionSPKIs: sortedB64(spkis(overrides.BlockedInterceptionSPKIs)),
    LimitedSubjects: limited,
  };
}
