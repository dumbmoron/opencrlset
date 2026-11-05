// The inclusion rules. No Node APIs: the explorer site imports this to explain
// the same decisions the build makes.

import { REASON } from "./reasons.ts";

export const TIERS = ["standard", "priority", "all"] as const;

export type Tier = (typeof TIERS)[number];

export interface Policy {
  maxLeafLifetimeDays: number;
  excludedReasons: number[];
  leafReasons: Record<Tier, number[] | null>;
  blockKeyReasons: number[];
}

export const POLICY: Policy = {
  // TLS server certificates may not be valid for longer than this (CA/B Forum
  // Baseline Requirements 6.3.2), so a leaf revoked earlier has certainly expired.
  maxLeafLifetimeDays: 398,
  // temporary holds, which no tier includes
  excludedReasons: [REASON.certificateHold, REASON.removeFromCRL],
  // leaf revocation reasons per tier; null means any.
  // standard: what the Chrome Root Program says CRLSets cover.
  // priority: also cessationOfOperation, like CRLite's "compat" channel.
  leafReasons: {
    standard: [REASON.keyCompromise, REASON.privilegeWithdrawn],
    priority: [REASON.keyCompromise, REASON.cessationOfOperation, REASON.privilegeWithdrawn],
    all: null,
  },
  // a CA certificate revoked for one of these means its private key is out, so
  // every tier blocks the key itself (BlockedSPKIs): revoking the certificates
  // we know of doesn't stop certificates nobody disclosed
  blockKeyReasons: [REASON.keyCompromise, REASON.cACompromise],
};

export type Verdict = "included" | "scope" | "hold" | "expired" | "reason";

// Issuers outside the store's scope only contribute revoked CA certificates.
// Revoked CA certificates are always included (unless on hold); leaves only
// while they can still be unexpired, and only for the tier's reasons.
export function tierVerdict(
  tier: Tier,
  revocation: { reason: number | null; date: number },
  ca: boolean,
  inScope: boolean,
  snapshotTime: number,
  policy: Policy = POLICY,
): Verdict {
  const { reason } = revocation;

  if (!inScope && !ca) return "scope";

  if (reason !== null && policy.excludedReasons.includes(reason)) return "hold";

  if (ca) return "included";

  if (revocation.date + policy.maxLeafLifetimeDays * 86400 < snapshotTime) return "expired";
  const reasons = policy.leafReasons[tier];

  return reasons === null || (reason !== null && reasons.includes(reason)) ? "included" : "reason";
}

// Reviewed additions to the CRLSet header (policy/overrides.json); see overrides.ts
export interface Justified {
  // why, and where it was decided
  reason: string;
  reference: string;
}

export interface Overrides {
  BlockedSPKIs: (Justified & { spkiSha256: string })[];
  KnownInterceptionSPKIs: (Justified & { spkiSha256: string })[];
  BlockedInterceptionSPKIs: (Justified & { spkiSha256: string })[];
  LimitedSubjects: (Justified & { subjectSha256: string; allowedSpkiSha256: string[] })[];
}
