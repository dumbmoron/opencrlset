# Verifying a build

## Provenance

Every file listed in a build's `SHA256SUMS` has a [build provenance
attestation][attestation] naming the commit and workflow run that
produced it.

```sh
base=https://crls.helium.computer/builds/<sequence>
curl -sLO "$base/crlset/standard/crl-set"
gh attestation verify crl-set --repo imputnet/opencrlset
```

## Rebuilding

With the same snapshot, commit (`snapshotTool.commit` in `report.json`)
and Node version (`snapshotTool.node`), a build produces the same bytes.

```sh
git checkout <commit>
pnpm install --frozen-lockfile
mkdir snapshot
curl -L "$base/snapshot.tar.zst" | zstd -d | tar -x -C snapshot
curl -LO "$base/google/crl-set"
node src/cli.ts build snapshot out --google crl-set
curl -sL "$base/SHA256SUMS" \
  | grep -v -e snapshot.tar.zst \
      -e '^.\{64\}  google/' -e '^.\{64\}  crx/' \
  | (cd out && sha256sum -c)
```

## CRXs

`crx/` needs the signing key to rebuild, so check it instead:

```sh
for tier in standard priority all; do
  curl -sLO "$base/crx/$tier.crx3"
  node src/cli.ts crx-verify $tier.crx3 --files out/crlset/$tier
done
```

## Inputs

The snapshot's `manifest.json` lists where and when each CRL was
fetched, and stores it under its SHA-256, so the inputs can be checked
against the CAs' servers.

[attestation]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
