#!/usr/bin/env bash
# Trust-ordered lazy-blob routing. All remotes are local throwaway repositories.
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"; COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok(){ printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }

LAB="$(mktemp -d -t commons-fetch-fallback-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/root" COMMONS_VIEM_DIR="$LAB/viem"
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@local
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@local
mkdir -p "$COMMONS_ROOT/registry/artifacts" "$COMMONS_ROOT/registry/ledger" \
  "$COMMONS_ROOT/store/sha256" "$COMMONS_VIEM_DIR/node_modules/viem"
git init -q "$COMMONS_ROOT"
git -C "$COMMONS_ROOT" config user.name test
git -C "$COMMONS_ROOT" config user.email test@local
touch "$COMMONS_ROOT/.seed"
git -C "$COMMONS_ROOT" add .seed
git -C "$COMMONS_ROOT" commit -qm seed

cat >"$COMMONS_VIEM_DIR/node_modules/viem/package.json" <<'MOCK'
{"type":"module","exports":{".":"./index.js"}}
MOCK
cat >"$COMMONS_VIEM_DIR/node_modules/viem/index.js" <<'MOCK'
export async function recoverMessageAddress({signature}) {
  if (!signature.startsWith("sig:")) throw new Error("bad fixture signature");
  return signature.slice(4);
}
MOCK

printf 'honest research bytes\n' >"$LAB/content"
DIGEST="$(sha256sum "$LAB/content" | cut -d' ' -f1)"
AID="ds-${DIGEST:0:8}"
BYTES="$(wc -c <"$LAB/content" | tr -d ' ')"
jq -n --arg id "$AID" --arg sha "$DIGEST" --argjson bytes "$BYTES" \
  '{schema:"rc.v1",id:$id,type:"dataset",title:"fallback target",
    content:{sha256:$sha,bytes:$bytes},links:[]}' \
  >"$COMMONS_ROOT/registry/artifacts/$AID.json"

mkremote(){
  local key="$1" mode="$2"
  local work="$LAB/work-$key" bare="$LAB/$key.git"
  git init -q "$work"
  git -C "$work" config user.name test
  git -C "$work" config user.email test@local
  mkdir -p "$work/store/sha256/${DIGEST:0:2}"
  if [ "$mode" = honest ]; then
    cp "$LAB/content" "$work/store/sha256/${DIGEST:0:2}/$DIGEST"
  elif [ "$mode" = poison ]; then
    printf 'poisoned bytes\n' >"$work/store/sha256/${DIGEST:0:2}/$DIGEST"
  else
    touch "$work/.empty"
  fi
  git -C "$work" add -A
  git -C "$work" commit -qm fixture
  git init -q --bare "$bare"
  git -C "$work" remote add origin "$bare"
  git -C "$work" push -q origin HEAD
}
mkremote absent absent
mkremote honest honest
mkremote poison poison

clear_remotes(){
  local name
  while read -r name; do [ -n "$name" ] && git -C "$COMMONS_ROOT" remote remove "$name"; done \
    < <(git -C "$COMMONS_ROOT" remote)
}
local_blob(){ printf '%s/store/sha256/%s/%s' "$COMMONS_ROOT" "${DIGEST:0:2}" "$DIGEST"; }
clear_blob(){ chmod u+w "$(local_blob)" 2>/dev/null || true; rm -f "$(local_blob)"; }
run_fetch(){ "$COMMONS" fetch "$AID" >"$LAB/out" 2>"$LAB/err"; }
snapshot_policy(){
  cp "$COMMONS_ROOT/registry/peers.json" "$LAB/peers.before"
  cp "$COMMONS_ROOT/.git/config" "$LAB/config.before"
}
policy_unchanged(){
  cmp -s "$LAB/peers.before" "$COMMONS_ROOT/registry/peers.json" &&
    cmp -s "$LAB/config.before" "$COMMONS_ROOT/.git/config"
}
printf '{"schema":"rc.v1","peers":[]}\n' >"$COMMONS_ROOT/registry/peers.json"

printf 'name-ordered fallback\n'
clear_remotes
git -C "$COMMONS_ROOT" remote add a-absent "$LAB/absent.git"
git -C "$COMMONS_ROOT" remote add z-honest "$LAB/honest.git"
snapshot_policy
if run_fetch && cmp -s "$LAB/content" "$(local_blob)"; then
  ok "omitted remote falls through to later configured remote"
else
  bad "omitted remote fallback"
fi
check "stable name order tries absent first" "$(grep -c "via a-absent: absent" "$LAB/out")" "1"
if policy_unchanged; then ok "fetch leaves peers and git config byte-identical"; else bad "fetch mutated policy"; fi

printf 'poison fallback\n'
clear_blob; clear_remotes
git -C "$COMMONS_ROOT" remote add a-poison "$LAB/poison.git"
git -C "$COMMONS_ROOT" remote add z-honest "$LAB/honest.git"
if run_fetch && cmp -s "$LAB/content" "$(local_blob)"; then
  ok "hash mismatch falls through to honest remote"
else
  bad "poison fallback"
fi
check "poison is logged as hash-mismatch" "$(grep -c "via a-poison: hash-mismatch" "$LAB/out")" "1"

printf 'explicit remote stays single-shot\n'
clear_blob; clear_remotes
git -C "$COMMONS_ROOT" remote add a-absent "$LAB/absent.git"
git -C "$COMMONS_ROOT" remote add z-honest "$LAB/honest.git"
if "$COMMONS" fetch "$AID" a-absent >"$LAB/out" 2>"$LAB/err"; then
  bad "explicit absent remote unexpectedly succeeded"
elif grep -q "a-absent does not carry the blob" "$LAB/err" && [ ! -e "$(local_blob)" ]; then
  ok "explicit remote keeps established hard failure without fallback"
else
  bad "explicit remote behavior changed"
fi

# Add a locally readable curated collection: announce host claims can now be a hint.
COLL_SPEC="$LAB/collection.json"
jq -n --arg aid "$AID" '{scope:"routing fixture",maintainers:[],
  members:[{id:$aid,role:"source"}]}' >"$COLL_SPEC"
CDIGEST="$(sha256sum "$COLL_SPEC" | cut -d' ' -f1)"
CID="cl-${CDIGEST:0:8}"
mkdir -p "$COMMONS_ROOT/store/sha256/${CDIGEST:0:2}"
cp "$COLL_SPEC" "$COMMONS_ROOT/store/sha256/${CDIGEST:0:2}/$CDIGEST"
CBYTES="$(wc -c <"$COLL_SPEC" | tr -d ' ')"
jq -n --arg id "$CID" --arg sha "$CDIGEST" --argjson bytes "$CBYTES" \
  '{schema:"rc.v1",id:$id,type:"collection",title:"routing collection",
    content:{sha256:$sha,bytes:$bytes},links:[]}' \
  >"$COMMONS_ROOT/registry/artifacts/$CID.json"

addr(){ printf '%s' "$1" | sha256sum | cut -c1-40 | sed 's/^/0x/'; }
FULL_CLAIM="$(addr full-claim)"
FULL_OTHER="$(addr full-other)"
DATA_CLAIM="$(addr data-claim)"
jq -n --arg a "$FULL_CLAIM" --arg b "$FULL_OTHER" --arg c "$DATA_CLAIM" \
  '{schema:"rc.v1",peers:[
    {addr:$a,agent:"full-claim",trust:"full"},
    {addr:$b,agent:"full-other",trust:"full"},
    {addr:$c,agent:"data-claim",trust:"datasets-only"}]}' \
  >"$COMMONS_ROOT/registry/peers.json"
LIVE="$(date -u -d '+60 days' +%Y-%m-%dT%H:%M:%SZ)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
announce(){
  local signer="$1" url="$2" host="$3"
  local spec="$LAB/announce-$signer.json"
  jq -n --arg signer "$signer" --arg url "$url" --arg host "$host" \
    --arg now "$NOW" --arg live "$LIVE" \
    '{announcer:$signer,remotes:[{url:$url}],hosts:
      (if $host == "" then [] else [{collection:$host,blobs:"all"}] end),
      refreshed:$now,expires:$live}' >"$spec"
  local digest id bytes
  digest="$(sha256sum "$spec" | cut -d' ' -f1)"; id="pa-${digest:0:8}"
  bytes="$(wc -c <"$spec" | tr -d ' ')"
  mkdir -p "$COMMONS_ROOT/store/sha256/${digest:0:2}"
  cp "$spec" "$COMMONS_ROOT/store/sha256/${digest:0:2}/$digest"
  jq -n --arg id "$id" --arg sha "$digest" --argjson bytes "$bytes" \
    '{schema:"rc.v1",id:$id,type:"peer-announce",title:"announce",
      content:{sha256:$sha,bytes:$bytes},links:[]}' \
    >"$COMMONS_ROOT/registry/artifacts/$id.json"
  jq -nc --arg id "$id" --arg sha "$digest" --arg signer "$signer" --arg sig "sig:$signer" \
    '{schema:"rc.v1",ts:"2026-08-05T00:00:00Z",agent:"fixture",
      action:"publish",id:$id,sha256:$sha,addr:$signer,sig:$sig}' \
    >"$COMMONS_ROOT/registry/ledger/${signer,,}.jsonl"
}
announce "$FULL_CLAIM" "$LAB/poison.git" "$CID"
announce "$FULL_OTHER" "$LAB/absent.git" ""
announce "$DATA_CLAIM" "$LAB/honest.git" "$CID"

printf 'announce hint and trust bands\n'
clear_blob; clear_remotes
git -C "$COMMONS_ROOT" remote add a-full-unclaimed "$LAB/absent.git"
git -C "$COMMONS_ROOT" remote add b-data-claimed "$LAB/honest.git"
git -C "$COMMONS_ROOT" remote add z-full-claimed "$LAB/poison.git"
snapshot_policy
if run_fetch && cmp -s "$LAB/content" "$(local_blob)"; then
  ok "trusted announce ordering still reaches honest fallback"
else
  bad "announce ordering fetch"
fi
FIRST="$(grep '^fetch ' "$LAB/out" | sed -n '1p')"
SECOND="$(grep '^fetch ' "$LAB/out" | sed -n '2p')"
if [[ "$FIRST" == *"via z-full-claimed: hash-mismatch"* ]]; then
  ok "collection claim reorders within full-trust band"
else
  bad "claimed full remote was not first ($FIRST)"
fi
if [[ "$SECOND" == *"via a-full-unclaimed: absent"* ]]; then
  ok "full-trust band remains ahead of datasets-only despite claim"
else
  bad "trust band was crossed ($SECOND)"
fi
if policy_unchanged; then ok "announce-routed fetch leaves peers and config unchanged"; else bad "announce-routed fetch mutated policy"; fi

printf 'sync member fallback\n'
clear_blob; clear_remotes
git -C "$COMMONS_ROOT" remote add origin "$LAB/absent.git"
git -C "$COMMONS_ROOT" remote add z-honest "$LAB/honest.git"
jq -n --arg cid "$CID" '{schema:"rc.v1",subscriptions:[{
  collection:$cid,remote:"origin",blobs:"members",executables:false,
  include_self_declared:false,follow_supersedes:"maintainer-signed",
  added:"2026-08-05T00:00:00Z"}]}' >"$COMMONS_ROOT/registry/subscriptions.json"
COMMONS_BIN="$COMMONS" CID="$CID" python3 - <<'PYSYNC' >"$LAB/out" 2>"$LAB/err"
import argparse, importlib.machinery, importlib.util, os
loader = importlib.machinery.SourceFileLoader("commons_cli", os.environ["COMMONS_BIN"])
spec = importlib.util.spec_from_loader(loader.name, loader)
commons = importlib.util.module_from_spec(spec)
loader.exec_module(commons)
commons.cmd_pull = lambda _args: None
commons.cmd_sync(argparse.Namespace(subscription=os.environ["CID"]))
PYSYNC
if cmp -s "$LAB/content" "$(local_blob)" &&
   grep -q "FETCHED $AID (via z-honest)" "$LAB/out"; then
  ok "sync falls back and reports the remote that served the member"
else
  bad "sync member fallback/report ($(tr '\n' ' ' <"$LAB/out"))"
fi

printf 'exhaustion reasons\n'
clear_blob; clear_remotes
git -C "$COMMONS_ROOT" remote add a-absent "$LAB/absent.git"
git -C "$COMMONS_ROOT" remote add z-poison "$LAB/poison.git"
if run_fetch; then
  bad "exhausted remotes unexpectedly succeeded"
elif grep -q "a-absent: absent" "$LAB/err" &&
     grep -q "z-poison: hash-mismatch" "$LAB/err"; then
  ok "exhaustion error lists each remote and failure class"
else
  bad "exhaustion error omitted per-remote reasons ($(tr '\n' ' ' <"$LAB/err"))"
fi

printf '\n\033[1mtest-fetch-fallback: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
