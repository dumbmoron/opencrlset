# Integrating opencrlset

## In a browser you build

Chromium only installs a CRLSet signed by the key whose hash is
`kCrlSetPublicKeySHA256` (in
`chrome/browser/component_updater/crl_set_component_installer.cc`),
which is Google's. To ship opencrlset:

1. Replace it with the hash of your own RSA key, or opencrlset's.
   `opencrlset crx-id key.pem` prints it, and the new component ID.
   Update anything in your browser keyed by the old ID.
2. Point the component updater at an update server for that component.
3. Sign the server's responses, or turn CUP off (below).

**CRXs.** opencrlset publishes signed ones in `builds/<sequence>/crx/`.
To sign with your own key instead:

```sh
opencrlset crx <build-dir> <out-dir> --key key.pem \
  [--previous-crx <dir> --puffin <path>]
```

It writes `<tier>.crx3`, an index `<tier>.json`, and patches from the
earlier CRXs it's given. The same build and key give the same bytes,
and `opencrlset crx-verify <file> --files <build-dir>/crlset/<tier>`
checks a CRX without the key.

**Patches** are about 1% of a full CRX between builds a day apart. They
need Chromium's own `puffin`; [`.github/actions/puffin`][puffin] builds
and caches it in GitHub Actions.

**Update server.** `opencrlset serve https://crls.helium.computer/`
answers from the newest build's index: `noupdate` to browsers that are
current, else the patch matching their cached CRX, then the full one.
Its logic is also `updateHandler` in `src/update-server.ts`, to put in
an existing server.

**CUP.** Chromium checks a signature on update responses, with
ML-DSA-44 by default, else ECDSA P-256. Either replace the public key in
`components/update_client/request_sender.cc` and run
`serve --cup-key <version>=<key.pem>`, or make `EnabledCupSigning()`
return `false`.

**Tiers.** `all` is about 145 MB, and the browser keeps it in memory.
Builds expire 7 days after their snapshot, so check for updates well
within that.

No browser has installed one of these CRXs yet: that needs one built
with a different `kCrlSetPublicKeySHA256`.

## In any Chromium browser

Works without changing the browser, if `chrome://components` lists
**CRLSet**.

1. Find the user data directory: **Profile Path** in `chrome://version`,
   minus its last part.
2. Close the browser, and run:

   ```sh
   scripts/install-crlset.sh <user-data-dir> [standard|priority|all]
   ```

   By hand: delete everything in the user data directory's
   `CertificateRevocation`, then put a build's `crlset/<tier>/crl-set`
   and `manifest.json` in `CertificateRevocation/<sequence>/`. If
   Google's folder stays, the browser keeps using it and deletes yours.

3. `chrome://components` should show a CRLSet version around 29 million.

Nothing updates it after that, so run the script on a schedule, at least
weekly. It can run while the browser is open; the new set loads at the
next start. To go back to Google's, delete `CertificateRevocation` and
restart.

[puffin]: ../.github/actions/puffin
