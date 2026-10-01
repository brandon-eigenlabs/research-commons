#!/usr/bin/env bash
# Regression for scripts/demo-hub.sh: the README's "Demo hub artifacts" table cites
# fixed ids, so this asserts they still resolve and that the generator is
# deterministic (same ids under two different throwaway signing keys).
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
GEN="$REPO/scripts/demo-hub.sh"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

LAB="$(mktemp -d -t commons-demo-hub-test-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT

head_ "build #1"
T1="$LAB/run1"
ROOT1="$(bash "$GEN" "$T1" 2>"$LAB/err1.txt")"
check "build #1 exits with a hub root" "$([ -d "$ROOT1" ] && echo yes)" "yes"
check "build #1 wrote ids.json" "$([ -f "$T1/ids.json" ] && echo yes)" "yes"

head_ "documented ids resolve"
DS=$(python3 -c "import json;print(json.load(open('$T1/ids.json'))['ds'])")
WF=$(python3 -c "import json;print(json.load(open('$T1/ids.json'))['wf'])")
SY=$(python3 -c "import json;print(json.load(open('$T1/ids.json'))['sy'])")
CL=$(python3 -c "import json;print(json.load(open('$T1/ids.json'))['cl'])")
check "documented dataset id" "$DS" "ds-efae742c"
check "documented workflow id" "$WF" "wf-1e4e0c5e"
check "documented synthesis id" "$SY" "sy-c775b533"
check "documented collection id" "$CL" "cl-304d7331"

head_ "verify PASS, chain grade T3"
check "verify PASSes" "$(COMMONS_ROOT="$ROOT1" "$COMMONS" verify "$SY" >/dev/null 2>&1; echo $?)" "0"
check "chain grade is T3 (weakest link: the attested dataset)" \
  "$(COMMONS_ROOT="$ROOT1" "$COMMONS" status "$SY" --brief 2>/dev/null | grep -oE 'chain=T[0-3]')" "chain=T3"

head_ "fsck clean (attribution + ledger)"
check "fsck --attribution --ledger is clean" \
  "$(COMMONS_ROOT="$ROOT1" "$COMMONS" fsck --attribution --ledger >/dev/null 2>&1; echo $?)" "0"

head_ "determinism: build #2 under a DIFFERENT throwaway key"
T2="$LAB/run2"
ROOT2="$(bash "$GEN" "$T2" 2>"$LAB/err2.txt")"
check "ids.json is byte-identical across runs" \
  "$(diff -q "$T1/ids.json" "$T2/ids.json" >/dev/null 2>&1 && echo same)" "same"
check "the two runs used different signing keys" \
  "$([ "$(cat "$T1/.demo.key")" != "$(cat "$T2/.demo.key")" ] && echo yes)" "yes"

printf '\n\033[1mtest-demo-hub: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
