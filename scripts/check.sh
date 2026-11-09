#!/usr/bin/env bash
# check.sh -- configure, build and run ctest for GCC, Clang and the sanitizer build.
# Usage: scripts/check.sh [gcc] [clang] [san]     (default: all three)
# Build trees go under $BUILD_ROOT (default: ./build) as <root>/<name>.
set -euo pipefail
cd "$(dirname "$0")/.."
root="${BUILD_ROOT:-build}"
targets=("$@"); [ ${#targets[@]} -eq 0 ] && targets=(gcc clang san)
for t in "${targets[@]}"; do
  case "$t" in
    gcc)   args=(-DCMAKE_CXX_COMPILER=g++) ;;
    clang) args=(-DCMAKE_CXX_COMPILER=clang++) ;;
    san)   args=(-DCMAKE_CXX_COMPILER=g++ -DSANITIZE=ON -DCMAKE_BUILD_TYPE=Debug) ;;
    *) echo "unknown target $t" >&2; exit 2 ;;
  esac
  echo "=== $t ==="
  cmake -S . -B "$root/$t" "${args[@]}" >/dev/null
  cmake --build "$root/$t" -j"$(nproc)" 2>&1 | grep -E "error|warning|Error" || true
  cmake --build "$root/$t" -j"$(nproc)" >/dev/null
  ctest --test-dir "$root/$t" --output-on-failure | tail -n 15
done
