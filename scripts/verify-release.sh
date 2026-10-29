#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: scripts/verify-release.sh TARGET OUTDIR" >&2
  exit 64
fi

target="$1"
outdir="$(mkdir -p "$2" && cd "$2" && pwd)"

cd "$(dirname "$0")/.."
here="$PWD"

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

second="$outdir/elsewhere/checkout-two"
rm -rf "$second"
mkdir -p "$second"
git archive HEAD | tar -x -C "$second"

echo "== first build, in $here"
"$here/scripts/build-release.sh" "$target" "$outdir/one"

echo "== second build, in $second, with its own cargo home"
(
  cd "$second"
  CARGO_HOME="$outdir/cargo-two" ./scripts/build-release.sh "$target" "$outdir/two"
)

binary="$outdir/one/inshape-$target"
one="$(sha256sum < "$binary")"
two="$(sha256sum < "$outdir/two/inshape-$target")"
echo "first:  $one"
echo "second: $two"
test "$one" = "$two"

description="$(file "$binary")"
echo "$description"
case "$description" in
  *"statically linked"* | *"static-pie linked"*) ;;
  *)
    echo "not a static binary" >&2
    exit 1
    ;;
esac

"$binary" --version

printf 'EXAMPLE_KEY\n' > "$outdir/allow"
code=0
env \
  INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=dummy-client-id \
  INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=dummy-client-secret \
  INFISICAL_PROJECT_ID=dummy-project-id \
  INFISICAL_ENV=dummy \
  INFISICAL_API_URL=http://127.0.0.1:1 \
  "$binary" --allowlist "$outdir/allow" -- true 2> "$outdir/stderr" || code=$?
cat "$outdir/stderr"
test "$code" -eq 64
grep -q https "$outdir/stderr"
echo "verified: $binary"
