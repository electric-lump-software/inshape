#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: e2e/expect.sh BINARY EXPECTED_EXIT" >&2
  exit 64
fi

bin="$1"
want="$2"
allow="$(dirname "$0")/allowlist"
fixed="E2E_ONE E2E_TWO INFISICAL_CANARY_ONE INFISICAL_CANARY_TWO"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

names_of() {
  while IFS= read -r -d '' rec; do
    printf '%s\n' "${rec%%=*}"
  done | { grep -v '^_$' || true; } | LC_ALL=C sort -u
}

status=0
"$bin" --allowlist "$allow" -- env -0 >"$tmp/out" 2>"$tmp/err" || status=$?

echo "inshape stderr:"
sed 's/^/  /' "$tmp/err"

if [ "$status" -ne "$want" ]; then
  echo "FAIL: exit $status, wanted $want"
  exit 1
fi

if [ "$want" -ne 0 ]; then
  if [ -s "$tmp/out" ]; then
    echo "FAIL: the command ran although inshape exited $status"
    exit 1
  fi
  echo "ok: exit $status and the command did not run"
  exit 0
fi

env -0 | names_of | { grep -v '^INFISICAL_' || true; } >"$tmp/expected"
for name in $fixed; do
  printf '%s\n' "$name" >>"$tmp/expected"
done
LC_ALL=C sort -u -o "$tmp/expected" "$tmp/expected"
names_of <"$tmp/out" >"$tmp/actual"

if ! diff "$tmp/expected" "$tmp/actual" >"$tmp/diff"; then
  echo "FAIL: the command's environment names differ (< wanted, > got):"
  cat "$tmp/diff"
  exit 1
fi

while IFS= read -r -d '' rec; do
  name="${rec%%=*}"
  value="${rec#*=}"
  for fixed_name in $fixed; do
    if [ "$name" = "$fixed_name" ] && [ -z "${value//[[:space:]]/}" ]; then
      echo "FAIL: $name is empty"
      exit 1
    fi
  done
done <"$tmp/out"

echo "ok: exit 0, the environment holds the host names plus $fixed, all non-empty"
