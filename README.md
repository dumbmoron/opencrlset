# opencrlset

a drop in replacement for google's proprietarily generated CRLSet,
built only from public data.

Builds run every 6 hours into [crls.helium.computer][site], under
`builds/<sequence>/`. The newest is copied to `latest/`, and
[`latest.json`][latest] points to it. The [explorer][] looks up a
serial or certificate in the newest build.

- using it in a browser, or shipping it in one: [integration.md][]
- checking a build is genuine, or rebuilding it: [verifying.md][]
- what goes in, and the dataset format: [policy.md][]

## Tiers

There are three CRLSets. They differ only in which **leaf** revocations
they keep.

- `standard`: keyCompromise (1) and privilegeWithdrawn (9). This matches
  what the [Chrome Root Program][crp] says CRLSets cover.
- `priority`: `standard` plus cessationOfOperation (5), like CRLite's
  "compat" channel.
- `all`: every reason except certificateHold (6) and removeFromCRL (8).

Not sure? Use `standard`. It's the one compared against Google's.

## Artifacts

- `crlset/*/crl-set`: the actual CRLSets
- `crlset/*/manifest.json`: component manifest for the `crl-set` next
  to it
- `revocations.ndjson.zst`: every revocation from every validated CRL,
  one JSON object per line
- `issuers.json`: every CA key, with its certificates, trust stores, CRL
  health and counts
- `sources.json`: every disclosed CRL URL, with its hash, validity and
  entry count, or why it was rejected
- `report.json`: totals, failures and the comparison with Google's
  CRLSet
- `crx/<tier>.crx3`: every tier as a signed CRX3, for Chromium's
  component updater
- `crx/<tier>.json`: what an update server needs: version, hashes,
  patches
- `crx/<tier>/<sha256>.puff`: patches from the last day's CRXs
- `google/`: the official CRLSet this build was compared against
- `snapshot.tar.zst`: the exact inputs: CCADB reports, every fetched CRL
  and the fetch log
- `SHA256SUMS`: hashes of everything above

## Policy (TLDR)

1. Fetch every CRL that any unexpired CCADB CA discloses.
2. Keep a CRL only if its signature checks out.
3. The dataset keeps everything.
4. The CRLSet tiers keep Chrome-trusted issuers, plus every revoked CA
   certificate.
5. Leaked CA keys get blocked outright.

Details in [policy.md][].

## Verifying

Every file in `SHA256SUMS` has a build provenance attestation:

```sh
gh attestation verify crlset/standard/crl-set \
  --repo imputnet/opencrlset
```

Builds are reproducible from `snapshot.tar.zst`; see [verifying.md][].

## Running locally

Needs node >=26 + pnpm

```sh
pnpm install
pnpm test
node src/cli.ts snapshot snapshot  # about 20k CRLs, a few hundred MB
node src/cli.ts fetch-google google
node src/cli.ts build snapshot out --google google/crl-set
node src/cli.ts dump out/crlset/standard/crl-set
node src/cli.ts check out/crlset/standard/crl-set \
  <issuer-spki-sha256> <serial-hex>
```

`site/` is a static explorer for the latest build. `pnpm site dev`
serves it with `out/` as `latest/`.

## License

AGPL-3.0-or-later, see [LICENSE][].

[integration.md]: docs/integration.md
[verifying.md]: docs/verifying.md
[policy.md]: docs/policy.md
[crp]: https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md
[LICENSE]: LICENSE
[site]: https://crls.helium.computer/index.html
[explorer]: https://crls.helium.computer/index.html
[latest]: https://crls.helium.computer/latest.json
