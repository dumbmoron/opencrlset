#!/usr/bin/env bash
# Builds Chromium's puffin from a chromium-tarballs release, whose archives
# carry the source with its dependencies and toolchains already fetched.
#
#   VERSION=157.0.8103.38 TARBALLS_URL=https://tarballs.imput.net \
#   TARBALLS_REPOSITORY=imputnet/chromium-tarballs OUT=<dir> build.sh
set -euo pipefail
: "${VERSION:?}" "${TARBALLS_URL:?}" "${TARBALLS_REPOSITORY:?}" "${OUT:?}"

# The source and toolchains take about 15 GiB, plus about 1 GiB of build.
NEEDED_GIB=20
free_gib() { df --output=avail -BG "$1" | tail -1 | tr -dc 0-9; }

pick_volume() {
  local best="" best_free=0 candidate free
  for candidate in "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" /mnt; do
    [ -d "$candidate" ] && [ -w "$candidate" ] || continue
    free=$(free_gib "$candidate")
    if [ "$free" -gt "$best_free" ]; then best=$candidate best_free=$free; fi
  done
  echo "$best"
}

volume=$(pick_volume)
if [ "$(free_gib "$volume")" -lt "$NEEDED_GIB" ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
  # what chromium-tarballs' setup_runner.py removes, except the tool cache,
  # which holds what setup-* actions installed for the rest of the job
  for path in /usr/local/lib/android /usr/share/dotnet /usr/local/swift /usr/share/swift \
    /usr/local/.ghcup /opt/ghc /usr/local/share/boost /opt/az /opt/microsoft; do
    sudo rm -rf -- "$path"
  done
  docker system prune --all --force >/dev/null
  volume=$(pick_volume)
fi
if [ "$(free_gib "$volume")" -lt "$NEEDED_GIB" ]; then
  echo "::error::puffin needs ${NEEDED_GIB} GiB free, the most is $(free_gib "$volume") GiB on $volume"
  exit 1
fi

work=$(mktemp -d "$volume/puffin-build.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
echo "building in $work ($(free_gib "$volume") GiB free)"

# The checksums come from the GitHub release, not from the archive host.
curl -fsSL -o "$work/SHA256SUMS" \
  "https://github.com/$TARBALLS_REPOSITORY/releases/download/chromium-$VERSION/SHA256SUMS"
for layer in base linux-x64; do
  name="chromium-$VERSION-$layer.tar.zst"
  expected=$(awk -v name="$name" '$2 == name { print $1 }' "$work/SHA256SUMS")
  [ -n "$expected" ] || { echo "::error::$name is not in SHA256SUMS"; exit 1; }
  # hash the archive as it streams through, and only trust the tree if it matches
  mkfifo "$work/hash"
  sha256sum < "$work/hash" > "$work/$layer.sha256" &
  curl -fsSL "$TARBALLS_URL/chromium-$VERSION/$name" | tee "$work/hash" | zstd -dc -T0 | tar -x -C "$work"
  wait $!
  rm "$work/hash"
  actual=$(cut -d' ' -f1 "$work/$layer.sha256")
  [ "$actual" = "$expected" ] || { echo "::error::$name: sha256 $actual, expected $expected"; exit 1; }
done

src="$work/chromium-$VERSION"
cd "$src"
# Start GN at puffin rather than //BUILD.gn, and define only puffin and what
# it depends on.
{
  cat .gn
  echo 'root = "//third_party/puffin:puffin"'
  echo 'root_patterns = [ "//third_party/puffin:puffin" ]'
} > .gn.puffin
mkdir -p out/puffin
cat > out/puffin/args.gn <<'EOF'
is_debug = false
is_component_build = false
symbol_level = 0
use_remoteexec = false
treat_warnings_as_errors = false
EOF
buildtools/linux64/gn gen out/puffin --dotfile=.gn.puffin
third_party/ninja/ninja -C out/puffin puffin

# A round trip, so a broken binary never reaches the cache. puffin picks the
# file type from the extension; .raw is plain data.
printf 'opencrlset puffin check, before' > "$work/a.raw"
printf 'opencrlset puffin check, after!' > "$work/b.raw"
out/puffin/puffin -puffdiff "$work/a.raw" "$work/b.raw" "$work/patch.puff"
out/puffin/puffin -puffpatch "$work/a.raw" "$work/check.raw" "$work/patch.puff"
cmp "$work/b.raw" "$work/check.raw"

mkdir -p "$OUT"
cp out/puffin/puffin "$OUT/puffin"
echo "built $OUT/puffin from Chromium $VERSION"
