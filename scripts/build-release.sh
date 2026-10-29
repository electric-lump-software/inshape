#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: scripts/build-release.sh TARGET OUTDIR" >&2
  exit 64
fi

target="$1"
outdir="$2"

case "$target" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
  *)
    echo "build-release: unsupported target: $target" >&2
    exit 64
    ;;
esac

cd "$(dirname "$0")/.."

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

underscored="${target//-/_}"
upper="$(printf '%s' "$underscored" | tr '[:lower:]' '[:upper:]')"

unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTC_WRAPPER \
  RUSTC_WORKSPACE_WRAPPER CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR \
  CARGO_BUILD_TARGET CARGO_BUILD_JOBS CARGO_PROFILE_RELEASE_LTO \
  CARGO_PROFILE_RELEASE_STRIP CARGO_PROFILE_RELEASE_PANIC \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS CARGO_PROFILE_RELEASE_OPT_LEVEL \
  CFLAGS CXXFLAGS CC CXX AR CPPFLAGS TARGET_CC TARGET_CFLAGS TARGET_AR \
  HOST_CC HOST_CFLAGS \
  "CC_$underscored" "CFLAGS_$underscored" "AR_$underscored" \
  "CARGO_TARGET_${upper}_LINKER" "CARGO_TARGET_${upper}_RUSTFLAGS"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$cargo_home=/cargo"
export "CFLAGS_$underscored=-ffile-prefix-map=$PWD=/build -ffile-prefix-map=$cargo_home=/cargo"
export "CC_$underscored=musl-gcc"
export CARGO_INCREMENTAL=0

env -u "CC_$target" -u "CFLAGS_$target" -u "AR_$target" -u "CXX_$target" \
  cargo build --release --locked --no-default-features --target "$target" --target-dir target

mkdir -p "$outdir"
cp "target/$target/release/inshape" "$outdir/inshape-$target"
sha256sum "$outdir/inshape-$target"
