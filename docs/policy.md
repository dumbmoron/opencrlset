# Policy

The rules are in [`src/policy.ts`][policy.ts].

## Which issuers

- **Dataset:** every CA in CCADB whose certificate hasn't expired,
  trusted or not.
- **CRLSet tiers:** issuers Chrome trusts (CCADB "Chrome Status"
  `Included` or `Trusted`), plus revoked CAs that chain to one, in case
  their key has another certificate.
- **CRLs:** every URL each CA discloses, full or partitioned, over plain
  HTTP if HTTPS fails to verify. The CRL's own signature is what counts.

## Which CRLs

- **Accepted:** it parses, and its signature verifies with a CCADB CA's
  key: the CA that disclosed the URL first, then any CA with the CRL's
  issuer name.
- **Rejected:** indirect CRLs and attribute-certificate CRLs.
- **Accepted with a warning** in `sources.json`: stale CRLs, delta CRLs,
  and partitioned CRLs whose IssuingDistributionPoint doesn't match.

When several CRLs list the same serial under the same key, the one with
the newest `thisUpdate` wins.

## Tiers

A CA certificate counts as revoked when its issuer's CRL lists it, or
CCADB marks it `Revoked`. Everything on a root's CRL counts as a CA
certificate.

- **Covered issuers only:** leaf revocations only count under the
  issuers above.
- **Revoked CAs everywhere:** revoked CA certificates go into every
  tier, even under issuers Chrome no longer trusts.
- **No holds:** certificateHold is excluded, even for CAs.
- **Expired leaves:** leaf revocations more than 398 days old are
  dropped. The dataset keeps them.
- **Compromised CA keys:** a disclosed CA certificate revoked for
  keyCompromise or cACompromise puts its key in `BlockedSPKIs`, listed
  under `blockedKeys` in `report.json`, unless another CCADB certificate
  still vouches for the key: an unrevoked one, or a root some store
  trusts. Then one CA can't block a key others stand behind, and the key
  is listed under `contestedKeys` instead.

## Overrides

Anything beyond CRL data goes in [`policy/overrides.json`][overrides],
with a reason and a link for every entry.

## Dataset format

`revocations.ndjson.zst` has one record per line, sorted by issuer, then
serial. A record, wrapped here:

```json
{
  "issuer": "<sha256 of issuer SPKI, hex>",
  "serial": "<hex>",
  "reason": 1,
  "revoked": "2026-01-01T00:00:00Z",
  "ca": false,
  "crl": "<sha256 of CRL>"
}
```

- `issuer`: SHA-256 of the issuing CA's DER SubjectPublicKeyInfo
- `serial`: DER INTEGER contents, redundant leading zeros removed
- `reason`: RFC 5280 CRLReason, `0` when the CRL gives none
- `revoked`: revocation time
- `ca`: a CCADB-disclosed CA certificate, or anything a root key revoked
- `crl`: SHA-256 of the CRL it came from

A CA certificate CCADB marks revoked but no fetched CRL lists has
`reason`, `revoked` and `crl` all `null`.

## Comparison with Google

`google` in `report.json` compares `standard` with Google's current
CRLSet:

- `shared`: serials in both
- `oursOnly`: serials only in ours
- `googleOnly.inDatasetWithOtherReason`: serials we have, with a reason
  `standard` leaves out
- `googleOnly.issuerKnownButNotInDataset`: issuer known, but no fetched
  CRL lists the serial
- `googleOnly.unknownIssuer`: issuer key we have no CRLs for
- `blockedSPKIs`, `blockedSPKIsShared`: keys Google blocks, and how many
  of them we block too

[policy.ts]: ../src/policy.ts
[overrides]: ../policy/overrides.json
