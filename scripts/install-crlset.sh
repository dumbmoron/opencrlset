#!/usr/bin/env bash
# Installs the newest opencrlset CRLSet into a Chromium-based browser's
# profile. See docs/integration.md.
#
#   scripts/install-crlset.sh <user-data-dir> [standard|priority|all]
#
# OPENCRLSET_URL picks another copy of the builds than crls.helium.computer.
#
# The first time, close the browser before running this. The new set is
# loaded the next time the browser starts.
set -euo pipefail

url=${OPENCRLSET_URL:-https://crls.helium.computer}
dir=${1:?usage: install-crlset.sh <user-data-dir> [standard|priority|all]}/CertificateRevocation
tier=${2:-standard}

sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }

# latest.json names the newest build, whose files never change, and their hashes
index=$(curl -fsSL "$url/latest.json")
version=$(jq -r .sequence <<<"$index")
build="$url/$(jq -r .path <<<"$index")crlset/$tier"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for file in crl-set manifest.json; do
  curl -fsSL -o "$tmp/$file" "$build/$file"
  expected=$(jq -r --arg path "crlset/$tier/$file" '.files[$path]' <<<"$index")
  if [ "$(sha256 <"$tmp/$file")" != "$expected" ]; then
    echo "$file: checksum mismatch" >&2
    exit 1
  fi
done

# While the folder of the version it last installed exists, the browser keeps
# using that one and deletes every other folder, so replace all of them.
rm -rf "$dir"
mkdir -p "$dir/$version"
mv "$tmp/crl-set" "$tmp/manifest.json" "$dir/$version/"
echo "installed CRLSet $version ($tier) in $dir; restart the browser to load it"
