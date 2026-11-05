// CRL entry reason codes (RFC 5280 5.3.1). No Node APIs: the site imports this.

export const REASON = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10,
} as const;

export const REASON_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(REASON).map(([name, code]) => [code, name]),
);

export const reasonName = (reason: number | null | undefined) =>
  reason === null || reason === undefined
    ? "none given"
    : (REASON_NAMES[reason] ?? `code ${reason}`);
