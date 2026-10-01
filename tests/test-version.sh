#!/usr/bin/env bash
# VERSION file, `commons --version` / `commons version`, symlink resolution, missing-VERSION
# fallback, and the package.json/VERSION drift guard. No registry needed for most of this.
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

W="$(mktemp -d -t commons-test-version-XXXXXX)"
trap 'rm -rf "$W"' EXIT
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

VFILE="$REPO/VERSION"
VCONTENT="$(cat "$VFILE" 2>/dev/null | tr -d '\n')"

head_ "VERSION file exists and matches the expected shape"
check "VERSION file exists" "$(test -f "$VFILE"; echo $?)" "0"
check "VERSION is non-empty" "$([ -n "$VCONTENT" ] && echo yes || echo no)" "yes"
check "VERSION is one line" "$(wc -l <"$VFILE" | tr -d ' ')" "1"

head_ "--version and the version subcommand"
EXPECTED="commons $VCONTENT (schema rc.v1)"
check "commons --version prints expected string" "$(env -u COMMONS_ROOT "$COMMONS" --version)" "$EXPECTED"
check "commons version subcommand prints the same string" "$(env -u COMMONS_ROOT "$COMMONS" version)" "$EXPECTED"
check "commons --version exits 0" "$(rc env -u COMMONS_ROOT "$COMMONS" --version)" "0"
check "commons version exits 0 without a hub" "$(rc env -u COMMONS_ROOT "$COMMONS" version)" "0"

head_ "version works through a symlink (wrapper-shim pattern)"
LINKDIR="$W/shim"; mkdir -p "$LINKDIR"
ln -s "$COMMONS" "$LINKDIR/commons"
check "symlinked invocation prints the same string" "$(env -u COMMONS_ROOT "$LINKDIR/commons" --version)" "$EXPECTED"

head_ "missing VERSION falls back to 'unknown' without crashing"
NOVER="$W/no-version-checkout"
mkdir -p "$NOVER/bin"
cp "$COMMONS" "$NOVER/bin/commons"
# Deliberately do not copy VERSION, lib/, or registry/ — just the script, to exercise the
# OSError fallback path in isolation.
check "missing-VERSION checkout still exits 0" "$(rc env -u COMMONS_ROOT python3 "$NOVER/bin/commons" --version)" "0"
check "missing-VERSION checkout reports unknown" "$(env -u COMMONS_ROOT python3 "$NOVER/bin/commons" --version)" "commons unknown (schema rc.v1)"

head_ "package.json version matches VERSION (drift guard)"
PKGVER="$(python3 -c "import json; print(json.load(open('$REPO/package.json'))['version'])" 2>/dev/null)"
check "package.json has a version field" "$([ -n "$PKGVER" ] && echo yes || echo no)" "yes"
check "package.json version equals VERSION" "$PKGVER" "$VCONTENT"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
