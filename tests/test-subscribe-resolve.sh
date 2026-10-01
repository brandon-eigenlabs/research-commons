#!/usr/bin/env bash
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"; COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok(){ printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
LAB="$(mktemp -d -t commons-subscribe-resolve-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/root" COMMONS_VIEM_DIR="$LAB/viem"
mkdir -p "$COMMONS_ROOT/registry/artifacts" "$COMMONS_ROOT/registry/ledger" \
  "$COMMONS_ROOT/store/sha256" "$COMMONS_VIEM_DIR/node_modules/viem"
git init -q "$COMMONS_ROOT"
git -C "$COMMONS_ROOT" config user.name test
git -C "$COMMONS_ROOT" config user.email test@local
cat >"$COMMONS_VIEM_DIR/node_modules/viem/package.json" <<'MOCK'
{"type":"module","exports":{".":"./index.js"}}
MOCK
cat >"$COMMONS_VIEM_DIR/node_modules/viem/index.js" <<'MOCK'
export async function recoverMessageAddress({signature}) {
  if (!signature.startsWith("sig:")) throw new Error("bad fixture signature");
  return signature.slice(4);
}
MOCK
addr(){ printf '%s' "$1" | sha256sum | cut -c1-40 | sed 's/^/0x/'; }
cid(){ printf '%s' "$1" | sha256sum | cut -c1-8 | sed 's/^/cl-/'; }
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LIVE="$(date -u -d '+60 days' +%Y-%m-%dT%H:%M:%SZ)"
PAST_REFRESH="$(date -u -d '-30 days' +%Y-%m-%dT%H:%M:%SZ)"
PAST_EXPIRES="$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)"
SINGLE="$(addr single)"; AMBIG_A="$(addr ambig-a)"; AMBIG_B="$(addr ambig-b)"
UNREG="$(addr unregistered)"; REVOKED="$(addr revoked)"; EXPIRED="$(addr expired)"
NONE="$(addr trust-none)"; UNCONFIG="$(addr unconfigured)"
CROSS_ORIG="$(addr cross-original)"; CROSS_OTHER="$(addr cross-other)"
ALIAS="$(addr alias)"
C_SINGLE="$(cid single)"; C_ZERO="$(cid zero)"; C_AMBIG="$(cid ambiguous)"
C_DISQUAL="$(cid disqualified)"; C_UNCONFIG="$(cid unconfigured)"
C_CROSS="$(cid cross-original)"; C_CROSS_OTHER="$(cid cross-other)"; C_ALIAS="$(cid alias)"
R_SINGLE="$LAB/single.git"; R_AMBIG_A="$LAB/ambig-a.git"; R_AMBIG_B="$LAB/ambig-b.git"
R_UNREG="$LAB/unregistered.git"; R_REVOKED="$LAB/revoked.git"; R_EXPIRED="$LAB/expired.git"
R_NONE="$LAB/none.git"; R_UNCONFIG="$LAB/unconfigured.git"; R_CROSS="$LAB/cross.git"
R_CROSS_OTHER="$LAB/cross-other.git"; R_ALIAS="$LAB/alias.git"
git -C "$COMMONS_ROOT" remote add hub "$R_SINGLE"
git -C "$COMMONS_ROOT" remote add ambig-a "$R_AMBIG_A"
git -C "$COMMONS_ROOT" remote add ambig-b "$R_AMBIG_B"
git -C "$COMMONS_ROOT" remote add disqual-unreg "$R_UNREG"
git -C "$COMMONS_ROOT" remote add disqual-revoked "$R_REVOKED"
git -C "$COMMONS_ROOT" remote add disqual-expired "$R_EXPIRED"
git -C "$COMMONS_ROOT" remote add disqual-none "$R_NONE"
git -C "$COMMONS_ROOT" remote add cross "$R_CROSS"
git -C "$COMMONS_ROOT" remote add cross-other "$R_CROSS_OTHER"
git -C "$COMMONS_ROOT" remote add zeta "$R_ALIAS"
git -C "$COMMONS_ROOT" remote add alpha "$R_ALIAS"
cat >"$COMMONS_ROOT/registry/peers.json" <<JSON
{"schema":"rc.v1","peers":[
 {"addr":"$SINGLE","agent":"single","trust":"full"},
 {"addr":"$AMBIG_A","agent":"ambig-a","trust":"full"},
 {"addr":"$AMBIG_B","agent":"ambig-b","trust":"datasets-only"},
 {"addr":"$REVOKED","agent":"revoked","trust":"full","revoked_at":"$NOW"},
 {"addr":"$EXPIRED","agent":"expired","trust":"full"},
 {"addr":"$NONE","agent":"none","trust":"none"},
 {"addr":"$UNCONFIG","agent":"unconfigured","trust":"datasets-only"},
 {"addr":"$CROSS_ORIG","agent":"cross-original","trust":"full"},
 {"addr":"$CROSS_OTHER","agent":"cross-other","trust":"none"},
 {"addr":"$ALIAS","agent":"alias","trust":"datasets-only"}
]}
JSON
cat >"$COMMONS_ROOT/registry/subscriptions.json" <<'JSON'
{"schema":"rc.v1","subscriptions":[]}
JSON
make_announce(){
  local signer="$1" agent="$2" remote="$3" collection="$4"
  local refreshed="$5" expires="$6" supersedes="${7:-}"
  python3 - "$COMMONS_ROOT" "$signer" "$agent" "$remote" "$collection" "$refreshed" "$expires" "$supersedes" <<'PYFIX'
import hashlib, json, os, sys
root, signer, agent, remote, collection, refreshed, expires, supersedes = sys.argv[1:]
spec = {"announcer": signer, "remotes": [{"url": remote, "transport": "git-local"}],
        "hosts": [{"collection": collection, "blobs": "members"}],
        "refreshed": refreshed, "expires": expires}
raw = (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode()
digest = hashlib.sha256(raw).hexdigest(); aid = "pa-" + digest[:8]
path = os.path.join(root, "store", "sha256", digest[:2], digest)
os.makedirs(os.path.dirname(path), exist_ok=True); open(path, "wb").write(raw)
manifest = {"schema": "rc.v1", "id": aid, "type": "peer-announce", "title": "fixture",
            "agent": agent, "content": {"sha256": digest, "filename": "announce.json", "bytes": len(raw)},
            "links": ([{"rel": "supersedes", "id": supersedes}] if supersedes else [])}
open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w").write(json.dumps(manifest, sort_keys=True) + "\n")
event = {"schema": "rc.v1", "action": "publish", "agent": agent, "id": aid,
         "sha256": digest, "ts": refreshed, "addr": signer, "sig": "sig:" + signer, "prev": None}
with open(os.path.join(root, "registry", "ledger", signer.lower() + ".jsonl"), "a") as f:
    f.write(json.dumps(event, sort_keys=True) + "\n")
print(aid)
PYFIX
}
PA_SINGLE="$(make_announce "$SINGLE" single "$R_SINGLE" "$C_SINGLE" "$NOW" "$LIVE")"
make_announce "$AMBIG_A" ambig-a "$R_AMBIG_A" "$C_AMBIG" "$NOW" "$LIVE" >/dev/null
make_announce "$AMBIG_B" ambig-b "$R_AMBIG_B" "$C_AMBIG" "$NOW" "$LIVE" >/dev/null
make_announce "$UNREG" unregistered "$R_UNREG" "$C_DISQUAL" "$NOW" "$LIVE" >/dev/null
make_announce "$REVOKED" revoked "$R_REVOKED" "$C_DISQUAL" "$NOW" "$LIVE" >/dev/null
make_announce "$EXPIRED" expired "$R_EXPIRED" "$C_DISQUAL" "$PAST_REFRESH" "$PAST_EXPIRES" >/dev/null
make_announce "$NONE" none "$R_NONE" "$C_DISQUAL" "$NOW" "$LIVE" >/dev/null
make_announce "$UNCONFIG" unconfigured "$R_UNCONFIG" "$C_UNCONFIG" "$NOW" "$LIVE" >/dev/null
PA_CROSS="$(make_announce "$CROSS_ORIG" cross-original "$R_CROSS" "$C_CROSS" "$NOW" "$LIVE")"
make_announce "$CROSS_OTHER" cross-other "$R_CROSS_OTHER" "$C_CROSS_OTHER" "$NOW" "$LIVE" "$PA_CROSS" >/dev/null
make_announce "$ALIAS" alias "$R_ALIAS" "$C_ALIAS" "$NOW" "$LIVE" >/dev/null

run_path(){
  local label="$1"; shift
  local peers_before config_before peers_after config_after
  peers_before="$(sha256sum "$COMMONS_ROOT/registry/peers.json" | cut -d' ' -f1)"
  config_before="$(sha256sum "$COMMONS_ROOT/.git/config" | cut -d' ' -f1)"
  "$@" >"$LAB/out" 2>&1; LAST_RC=$?
  peers_after="$(sha256sum "$COMMONS_ROOT/registry/peers.json" | cut -d' ' -f1)"
  config_after="$(sha256sum "$COMMONS_ROOT/.git/config" | cut -d' ' -f1)"
  if [ "$peers_before" = "$peers_after" ] && [ "$config_before" = "$config_after" ]; then
    ok "$label leaves peers.json and git config byte-identical"
  else
    bad "$label leaves peers.json and git config byte-identical"
  fi
}

run_path single "$COMMONS" subscribe "$C_SINGLE" --blobs members
check "single candidate succeeds" "$LAST_RC" "0"
check "resolved remote is reported" "$(grep -Fc "resolved remote 'hub' from announce $PA_SINGLE" "$LAB/out")" "1"
check "subscription records resolved remote" "$(jq -r --arg c "$C_SINGLE" '.subscriptions[]|select(.collection==$c)|.remote' "$COMMONS_ROOT/registry/subscriptions.json")" "hub"

run_path zero "$COMMONS" subscribe "$C_ZERO"
if [ "$LAST_RC" -ne 0 ]; then ok "zero candidate refuses"; else bad "zero candidate refuses"; fi

run_path ambiguous "$COMMONS" subscribe "$C_AMBIG"
if [ "$LAST_RC" -ne 0 ]; then ok "two-signer ambiguity refuses"; else bad "two-signer ambiguity refuses"; fi
check "ambiguity is explained" "$(grep -Fc 'is ambiguous; specify a remote' "$LAB/out")" "1"

run_path disqualified "$COMMONS" subscribe "$C_DISQUAL"
if [ "$LAST_RC" -ne 0 ]; then ok "unregistered/revoked/expired/trust-none announcers never resolve"; else bad "unregistered/revoked/expired/trust-none announcers never resolve"; fi

run_path unconfigured "$COMMONS" subscribe "$C_UNCONFIG"
if [ "$LAST_RC" -ne 0 ]; then ok "unconfigured candidate refuses"; else bad "unconfigured candidate refuses"; fi
SUGGESTED="peer-${UNCONFIG:2:8}"
check "unconfigured refusal suggests git remote add" "$(grep -Fxc "    git remote add $SUGGESTED $R_UNCONFIG" "$LAB/out")" "1"

run_path cross-signer "$COMMONS" subscribe "$C_CROSS"
check "cross-signer supersede does not remove original candidate" "$LAST_RC" "0"
check "cross-signer path keeps original remote" "$(jq -r --arg c "$C_CROSS" '.subscriptions[]|select(.collection==$c)|.remote' "$COMMONS_ROOT/registry/subscriptions.json")" "cross"

run_path aliases "$COMMONS" subscribe "$C_ALIAS"
check "same URL under two aliases resolves" "$LAST_RC" "0"
check "aliases choose lexicographically first" "$(jq -r --arg c "$C_ALIAS" '.subscriptions[]|select(.collection==$c)|.remote' "$COMMONS_ROOT/registry/subscriptions.json")" "alpha"
check "alias choice is explained" "$(grep -Fc "chose 'alpha' lexicographically" "$LAB/out")" "1"

run_path explicit "$COMMONS" subscribe "$C_ZERO" manual
check "explicit remote still wins" "$LAST_RC" "0"
check "explicit remote is recorded" "$(jq -r --arg c "$C_ZERO" '.subscriptions[]|select(.collection==$c)|.remote' "$COMMONS_ROOT/registry/subscriptions.json")" "manual"

printf '\n\033[1mtest-subscribe-resolve: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
