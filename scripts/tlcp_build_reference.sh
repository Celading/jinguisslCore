#!/usr/bin/env bash
# Test-only counterpart; never linked into JinguiSSL.
set -euo pipefail
reference="$(cd "${1:?usage: tlcp_build_reference.sh reference-source}" && pwd)"
script_root="$(cd "$(dirname "$0")" && pwd)"
expected=586d8aa6e8581a23a202d107e0e2af8087c18829
test "$(git -C "$reference" rev-parse HEAD)" = "$expected"
git -C "$reference" diff --exit-code HEAD --
cmake -S "$reference" -B "$reference/build" -DHITLS_BUILD_PROFILE=full
cmake --build "$reference/build" -j2
cc "$script_root/tlcp_reference_peer.c" \
  -I"$reference/include/tls" -I"$reference/include/crypto" \
  -I"$reference/include/bsl" -I"$reference/include/pki" \
  -L"$reference/build" -lhitls_tls -lhitls_pki -lhitls_crypto -lhitls_bsl \
  -Wl,-rpath,"$reference/build" -o "$reference/build/tlcp-reference-peer"
printf 'reference_commit=%s\n' "$expected"
