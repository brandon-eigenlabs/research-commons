#!/usr/bin/env bash
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"; COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok(){ printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
LAB="$(mktemp -d -t commons-suggest-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/root" COMMONS_VIEM_DIR="$LAB/viem"
mkdir -p "$COMMONS_ROOT/registry/artifacts" "$COMMONS_ROOT/registry/ledger" "$COMMONS_ROOT/store/sha256" "$COMMONS_VIEM_DIR/node_modules/viem"
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
TRUSTED="$(addr trusted)"; UNREGISTERED="$(addr unregistered)"
REVOKED="$(addr revoked)"; EXPIRED="$(addr expired)"; MISSING="$(addr missing)"
CTRUSTED="$(cid trusted)"; CNEW="$(cid new)"; CREVOKED="$(cid revoked)"
CEXPIRED="$(cid expired)"; CMISSING="$(cid missing)"
R_TRUSTED="$LAB/trusted.git"; R_NEW="$LAB/new.git"
R_REVOKED="$LAB/revoked.git"; R_EXPIRED="$LAB/expired.git"; R_MISSING="$LAB/missing.git"
git -C "$COMMONS_ROOT" remote add trusted "$R_TRUSTED"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LIVE="$(date -u -d '+60 days' +%Y-%m-%dT%H:%M:%SZ)"
PAST_REFRESH="$(date -u -d '-30 days' +%Y-%m-%dT%H:%M:%SZ)"
PAST_EXPIRES="$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)"
cat >"$COMMONS_ROOT/registry/peers.json" <<JSON
{"schema":"rc.v1","peers":[
  {"addr":"$TRUSTED","agent":"trusted-agent","trust":"full"},
  {"addr":"$REVOKED","agent":"revoked-agent","trust":"datasets-only","revoked_at":"$NOW"},
  {"addr":"$EXPIRED","agent":"expired-agent","trust":"datasets-only"}
]}
JSON
cat >"$COMMONS_ROOT/registry/subscriptions.json" <<JSON
{"schema":"rc.v1","subscriptions":[{"collection":"$CTRUSTED","remote":"trusted","blobs":"members"}]}
JSON
make_announce(){
  local signer="$1" agent="$2" remote="$3" collection="$4"
  local refreshed="$5" expires="$6" supersedes="${7:-}" missing="${8:-no}"
  python3 - "$COMMONS_ROOT" "$signer" "$agent" "$remote" "$collection" "$refreshed" "$expires" "$supersedes" "$missing" <<'PYFIX'
import hashlib, json, os, sys
root, signer, agent, remote, collection, refreshed, expires, supersedes, missing = sys.argv[1:]
spec = {"announcer": signer, "remotes": [{"url": remote, "transport": "git-local", "note": agent}],
        "hosts": [{"collection": collection, "blobs": "members"}],
        "refreshed": refreshed, "expires": expires}
raw = (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode()
digest = hashlib.sha256(raw).hexdigest(); aid = "pa-" + digest[:8]
path = os.path.join(root, "store", "sha256", digest[:2], digest)
if missing != "yes":
    os.makedirs(os.path.dirname(path), exist_ok=True); open(path, "wb").write(raw)
manifest = {"schema": "rc.v1", "id": aid, "type": "peer-announce", "title": "fixture announce",
            "agent": agent, "content": {"sha256": digest, "filename": "announce.json", "bytes": len(raw)},
            "links": ([{"rel": "supersedes", "id": supersedes}] if supersedes else [])}
open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w").write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
event = {"schema": "rc.v1", "action": "publish", "agent": agent, "id": aid, "sha256": digest,
         "ts": refreshed, "addr": signer, "sig": "sig:" + signer, "prev": None}
ledger = os.path.join(root, "registry", "ledger", signer.lower() + ".jsonl")
with open(ledger, "a") as f: f.write(json.dumps(event, sort_keys=True) + "\n")
print(aid)
PYFIX
}
OLD="$(make_announce "$TRUSTED" trusted-agent "$R_TRUSTED" "$CTRUSTED" "$NOW" "$LIVE")"
CROSS="$(make_announce "$UNREGISTERED" unregistered "$R_NEW" "$CNEW" "$NOW" "$LIVE" "$OLD")"
REV="$(make_announce "$REVOKED" revoked-agent "$R_REVOKED" "$CREVOKED" "$NOW" "$LIVE")"
EXP="$(make_announce "$EXPIRED" expired-agent "$R_EXPIRED" "$CEXPIRED" "$PAST_REFRESH" "$PAST_EXPIRES")"
MISS="$(make_announce "$MISSING" missing-agent "$R_MISSING" "$CMISSING" "$NOW" "$LIVE" "" yes)"
PEERS_BEFORE="$(sha256sum "$COMMONS_ROOT/registry/peers.json" | cut -d' ' -f1)"
CONFIG_BEFORE="$(sha256sum "$COMMONS_ROOT/.git/config" | cut -d' ' -f1)"
SUBS_BEFORE="$(sha256sum "$COMMONS_ROOT/registry/subscriptions.json" | cut -d' ' -f1)"
LEDGER_BEFORE="$(find "$COMMONS_ROOT/registry/ledger" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
"$COMMONS" peer suggest --json >"$LAB/suggest.json"
"$COMMONS" peer suggest >"$LAB/suggest.txt"
"$COMMONS" peer suggest --all >"$LAB/all.txt"
check "peers.json remains byte-identical" "$(sha256sum "$COMMONS_ROOT/registry/peers.json" | cut -d' ' -f1)" "$PEERS_BEFORE"
check "git config remains byte-identical" "$(sha256sum "$COMMONS_ROOT/.git/config" | cut -d' ' -f1)" "$CONFIG_BEFORE"
check "subscriptions remain byte-identical" "$(sha256sum "$COMMONS_ROOT/registry/subscriptions.json" | cut -d' ' -f1)" "$SUBS_BEFORE"
check "ledger remains byte-identical" "$(find "$COMMONS_ROOT/registry/ledger" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)" "$LEDGER_BEFORE"
if jq -e '
  keys == ["announcers","manifest_only","schema"] and .schema == "rc.peer-suggest.v1" and
  (.manifest_only | type == "number") and (.announcers | type == "array") and
  (all(.announcers[]; (keys == ["agent","announce","collections","commands","expiry","manifest_only",
    "registered","remotes","revoked","signer","trust"]) and
    (.expiry | has("at") and has("state")) and (.remotes | type == "array") and
    (.collections | type == "array") and (.commands | type == "array")))
' "$LAB/suggest.json" >/dev/null; then ok "--json shape is stable"; else bad "--json shape is stable"; fi
check "cross-signer supersede leaves original resolved" "$(jq -r --arg s "${TRUSTED,,}" '.announcers[]|select(.signer==$s)|.announce' "$LAB/suggest.json")" "$OLD"
check "cross-signer announce remains its own signer's tip" "$(jq -r --arg s "${UNREGISTERED,,}" '.announcers[]|select(.signer==$s)|.announce' "$LAB/suggest.json")" "$CROSS"
check "manifest-only blob is counted" "$(jq -r '.manifest_only' "$LAB/suggest.json")" "1"
check "configured URL is recognized" "$(jq -r --arg s "${TRUSTED,,}" '.announcers[]|select(.signer==$s)|.remotes[0].configured' "$LAB/suggest.json")" "true"
check "existing subscription is recognized" "$(jq -r --arg s "${TRUSTED,,}" '.announcers[]|select(.signer==$s)|.collections[0].subscribed' "$LAB/suggest.json")" "true"
RNAME="peer-${UNREGISTERED:2:8}"
PEER_CMD="commons peer add ${UNREGISTERED,,} --agent-id unregistered --trust datasets-only"
REMOTE_CMD="git remote add $RNAME $R_NEW"
SUB_CMD="commons subscribe $CNEW $RNAME"
check "exact peer-add command is shown" "$(grep -Fxc "    $PEER_CMD" "$LAB/suggest.txt")" "1"
check "exact git-remote command is shown" "$(grep -Fxc "    $REMOTE_CMD" "$LAB/suggest.txt")" "1"
check "exact subscribe command is shown" "$(grep -Fxc "    $SUB_CMD" "$LAB/suggest.txt")" "1"
check "revoked signer hidden by default" "$(grep -Fc "${REVOKED,,}" "$LAB/suggest.txt")" "0"
check "revoked signer shown with --all" "$(grep -Fc "${REVOKED,,} — REVOKED" "$LAB/all.txt")" "1"
check "expired announce is marked" "$(grep -Fc "${EXPIRED,,}" "$LAB/suggest.txt")" "1"
check "expired announce has no remote action" "$(grep -Fc "git remote add peer-${EXPIRED:2:8}" "$LAB/suggest.txt")" "0"
check "expired announce explains inaction" "$(grep -Fc 'no actions suggested: announce is expired' "$LAB/suggest.txt")" "1"
printf '\n\033[1mtest-suggest: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
