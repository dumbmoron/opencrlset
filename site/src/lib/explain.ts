// Why each CRLSet tier includes or excludes a revocation, decided by the same
// tierVerdict() the build uses.

import type { ExplorerMeta, ExplorerRecord } from "opencrlset/explorer-format";
import { TIERS, tierVerdict, type Tier, type Verdict } from "opencrlset/policy";
import { reasonName } from "opencrlset/reasons";

export { TIERS, reasonName, type Tier };

export interface Revocation {
  // issuer index, or the SPKI hash of an issuer outside CCADB
  issuer: number | string;
  serial: string;
  reason: number | null;
  // Unix seconds
  revoked: number | null;
  // index into the issuer's CRLs, -1 for none
  crl: number;
  caDisclosed: boolean;
  caByRoot: boolean;
  ca: boolean;
  google: boolean;
  googleOnly: boolean;
  added: boolean;
  // what the build decided
  tiers: Record<Tier, boolean>;
}

export function decodeRecord(line: ExplorerRecord, flags: ExplorerMeta["flags"]): Revocation {
  const [issuer, serial, reason, revoked, crl, bits] = line;

  return {
    issuer,
    serial,
    reason,
    revoked,
    crl,
    caDisclosed: Boolean(bits & flags.caDisclosed),
    caByRoot: Boolean(bits & flags.caByRoot),
    ca: Boolean(bits & (flags.caDisclosed | flags.caByRoot)),
    google: Boolean(bits & flags.google),
    googleOnly: Boolean(bits & flags.googleOnly),
    added: Boolean(bits & flags.added),
    tiers: {
      standard: Boolean(bits & flags.standard),
      priority: Boolean(bits & flags.priority),
      all: Boolean(bits & flags.all),
    },
  };
}

type ExplainMeta = Pick<ExplorerMeta, "policy" | "snapshotTime" | "store">;

// "missing": only Google's CRLSet has it, so no tier could
export function verdictFor(
  tier: Tier,
  record: Revocation,
  inScope: boolean,
  meta: ExplainMeta,
): Verdict | "missing" {
  if (record.googleOnly) return "missing";
  const snapshotTime = Date.parse(meta.snapshotTime) / 1000;

  return tierVerdict(
    tier,
    { reason: record.reason, date: record.revoked ?? 0 },
    record.ca,
    inScope,
    snapshotTime,
    meta.policy,
  );
}

const LABELS: Record<Exclude<Verdict, "included"> | "missing", string> = {
  missing: "only in Google's set",
  scope: "issuer out of scope",
  hold: "on hold",
  expired: "expired",
  reason: "reason not in tier",
};

// Whether the build put the record in a tier, and if not, why. A verdict that
// disagrees with the build's would be a bug in one of the two.
export function tierStatus(tier: Tier, record: Revocation, inScope: boolean, meta: ExplainMeta) {
  const verdict = verdictFor(tier, record, inScope, meta);
  const included = record.tiers[tier];
  const disagrees = !record.googleOnly && (verdict === "included") !== included;

  return { included, why: verdict === "included" ? undefined : LABELS[verdict], disagrees };
}

// Hex serial as the build stores it: no separators, no leading zero bytes.
export function canonicalSerial(input: string): string | undefined {
  let hex = input
    .trim()
    .toLowerCase()
    .replace(/^0x/, "")
    .replace(/[\s:.-]/g, "");

  if (!/^[0-9a-f]+$/.test(hex)) return undefined;

  if (hex.length % 2) hex = "0" + hex;

  while (hex.length > 2 && hex.startsWith("00")) hex = hex.slice(2);

  return hex;
}
