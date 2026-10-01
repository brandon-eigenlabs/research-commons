#!/usr/bin/env bash
# Cold-clone behavior: derived index self-heals and drift warnings remain local.
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC \
      COMMONS_REQUIRE_SIG COMMONS_CONTAINER_CMD COMMONS_VIEM_DIR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-cold-path-XXXXXX)"
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"
mkdir -p "$COMMONS_ROOT/registry/artifacts" "$COMMONS_ROOT/store/sha256" "$W"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
manifest() {
  python3 - "$COMMONS_ROOT/registry/artifacts" "$1" "$2" "$3" <<'PY'
import hashlib, json, os, sys
art, aid, title, description = sys.argv[1:]
digest = hashlib.sha256((aid + title).encode()).hexdigest()
m = {
    "schema": "rc.v1", "id": aid, "type": "dataset", "title": title,
    "description": description, "tags": ["cold-path"], "agent": "fixture",
    "created": "2026-08-07T00:00:00Z", "content": {
        "sha256": digest, "filename": aid + ".txt", "bytes": 0,
    },
    "verification": {"tier": "T3", "criteria": "test fixture"},
    "links": [],
}
with open(os.path.join(art, aid + ".json"), "w") as f:
    json.dump(m, f, sort_keys=True)
PY
}

AID=ds-cold0001
manifest "$AID" "Cold Path Nebula" "coldclone searchable fixture"

printf '\n\033[1mfresh clone index repair\033[0m\n'
check "fresh search exits 0" "$(rc c search coldclone)" "0"
check "fresh search returns its hit" "$(grep -c "$AID" "$W/out.txt")" "1"
check "fresh search reports one bounded rebuild" \
  "$(grep -c '^index missing/stale — rebuilding (1 artifacts)$' "$W/err.txt")" "1"

rm -f "$COMMONS_ROOT/registry/index.sqlite"
check "fresh list exits 0" "$(rc c list --type dataset)" "0"
check "fresh list returns its hit" "$(grep -c "$AID" "$W/out.txt")" "1"
check "fresh list reports one bounded rebuild" \
  "$(grep -c '^index missing/stale — rebuilding (1 artifacts)$' "$W/err.txt")" "1"

printf '\n\033[1mstale index repair\033[0m\n'
python3 - "$COMMONS_ROOT/registry/index.sqlite" "$AID" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("DELETE FROM art_fts WHERE id=?", (sys.argv[2],))
con.commit()
PY
check "search repairs a deleted index row" "$(rc c search coldclone)" "0"
check "deleted-row repair reflects manifest truth" "$(grep -c "$AID" "$W/out.txt")" "1"
check "deleted-row mismatch reports rebuild" \
  "$(grep -c '^index missing/stale — rebuilding (1 artifacts)$' "$W/err.txt")" "1"

BID=ds-cold0002
manifest "$BID" "Backdoor Comet" "behindindex newly added fixture"
check "search repairs a manifest added behind the index" "$(rc c search behindindex)" "0"
check "added-manifest repair returns new hit" "$(grep -c "$BID" "$W/out.txt")" "1"
check "added-manifest mismatch reports new count" \
  "$(grep -c '^index missing/stale — rebuilding (2 artifacts)$' "$W/err.txt")" "1"

printf '\n\033[1manchor drift warning ownership\033[0m\n'
mkdir -p "$COMMONS_ROOT/registry/ledger"
: > "$COMMONS_ROOT/registry/ledger/local.jsonl"
rc c status "$AID" >/dev/null
check "ledger-less status emits no drift warning" \
  "$(grep -c 'local chain drifted' "$W/err.txt")" "0"
printf '%s\n' '{"action":"publish","agent":"fixture","id":"ds-cold0001","sha256":"computed-by-fixture","ts":"2000-01-01T00:00:00Z"}' \
  > "$COMMONS_ROOT/registry/ledger/local.jsonl"
rc c status "$AID" >/dev/null
check "old own unanchored entry still warns" \
  "$([ "$(grep -c 'local chain drifted' "$W/err.txt")" -eq 1 ] && echo yes)" "yes"

printf '\n\033[1mexplicit reindex\033[0m\n'
check "explicit reindex exits 0" "$(rc c reindex)" "0"
check "explicit reindex output is unchanged" "$(cat "$W/out.txt")" "reindexed 2 artifacts"
check "explicit reindex adds no repair warning" "$(wc -c < "$W/err.txt" | tr -d ' ')" "0"
check "explicit reindex remains searchable" "$(c search behindindex 2>/dev/null | grep -c "$BID")" "1"

printf '\ntest-cold-path: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
