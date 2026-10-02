#!/usr/bin/env bash
# Issue #41: an edit to the manifest of an already-held artifact must not merge unchecked.
#
# Before #41, `pull` compared content hashes, called a manifest-only edit "already
# present", skipped every check and then merged it; `hub check --base` only looked at
# added and deleted manifests. A peer could rewrite tier, criteria, licence,
# obtainability, title or links and every gate passed.
#
# What this pins:
#   1. the issue's repro (manifest-only edit, no ledger line) is refused by `pull`
#      (also on --dry-run) and fails `hub check --base`, with the changed fields named
#   2. a `publish --force` by the artifact's own publisher passes both gates
#   3. a `publish --force` by a key with no authority over the artifact does not
#   4. the legitimate unsigned-by-republish writers still flow: submit (fulfills),
#      accept (accepted), attest (attested_by)
#   5. an annotation with no ledger event behind it, and a link removal, are refused
#   6. KNOWN GAP, pinned so it is not mistaken for coverage: an edit committed after a
#      genuine republish in the same range rides on it (closed by signing manifests,
#      the follow-up designed with #10)
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

LAB="$(mktemp -d -t commons-test-manifest-edit-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
W="$LAB/work"; mkdir -p "$W"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
KL="$LAB/lead.key"; KC="$LAB/contrib.key"
for k in "$KL" "$KC"; do
  python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$k"; chmod 600 "$k"
done
HL="$LAB/hub-lead"; HC="$LAB/hub-contrib"; BARE="$LAB/hub.git"

L()  { ( cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
C()  { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KC" "$COMMONS" "$@" ); }
# The lead's own key, working in the contributor's clone (a second machine, same identity).
LC() { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both() { cat "$W/out.txt" "$W/err.txt"; }

"$COMMONS" hub init "$HL" --name manifest-edit >/dev/null 2>&1
ADDR_L=$(L peer whoami 2>/dev/null | head -1)
if [ -z "$ADDR_L" ]; then
  printf '\033[33mtest-manifest-edit: signer not functional — skipping\033[0m\n'; exit 0
fi
# Not C(): the contributor clone does not exist yet.
ADDR_C=$( (cd "$HL" && COMMONS_ROOT="$HL" COMMONS_SIGNING_KEY="$KC" "$COMMONS" peer whoami) 2>/dev/null | head -1)
L peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1
L peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
cp "$REPO/registry/exec-policy.example.json" "$HL/registry/exec-policy.json"

edit() {  # edit <root> <id> <python statements on m>
  python3 - "$1/registry/artifacts/$2.json" "$3" <<'PY'
import json, sys
p, code = sys.argv[1:3]; m = json.load(open(p)); exec(code)
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
}
field() { python3 -c 'import json,sys;m=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))' \
            "$1/registry/artifacts/$2.json" "$3"; }
branch() { ( cd "$HC" && git checkout -q main && git reset -q --hard origin/main \
             && git checkout -q -B "$1" ); }
cpush()  { ( cd "$HC" && git add registry store && git commit -qm "$1" \
             && git push -q -f origin "HEAD:$(git rev-parse --abbrev-ref HEAD)" ); }
lpull()  { rc L pull origin --branch "$1" "${@:2}"; }
hcheck() { ( cd "$HC" && COMMONS_ROOT="$HC" "$COMMONS" hub check --base origin/main ) \
             >"$W/out.txt" 2>&1; echo $?; }
lreset() { ( cd "$HL" && git reset -q --hard "$1" ); }

# ---------------------------------------------------------------- fixtures
head_ "fixtures: the lead's T3 dataset, a workflow and a task (beneficiary = lead)"
printf 'reading\n1\n2\n' > "$W/r.csv"
DS=$(L publish dataset "$W/r.csv" "readings" --tier T3 --criteria "hand-transcribed" \
       --license CC0-1.0 --obtainability restricted 2>/dev/null | tail -1)
check "dataset published" "$(echo "$DS" | grep -cE '^ds-[0-9a-f]{8}$')" "1"
printf 'reading\n3\n' > "$W/t3.csv"
T3=$(L publish dataset "$W/t3.csv" "observation" --tier T3 --criteria "GET /x" \
       --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
cat > "$W/step.py" <<'PY'
import json, os
json.dump({"n": 1}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
python3 - "$W/wf.json" "$DS" "$W/step.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF=$(L publish workflow "$W/wf.json" "wf" 2>/dev/null | tail -1)
python3 - "$W/task.json" "$DS" "$WF" "$ADDR_L" <<'PY'
import json, sys
out, ds, wf, ben = sys.argv[1:5]
json.dump({"objective": "count", "priority": 2, "expires": "2099-01-01T00:00:00Z",
           "inputs": [{"id": ds}], "execution": {"workflow": wf}, "max_claims": 2,
           "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
           "beneficiary": {"agent": "lead", "addr": ben}},
          open(out, "w"), indent=2, sort_keys=True)
PY
TK=$(L publish task "$W/task.json" "count task" 2>/dev/null | tail -1)
check "task published" "$(echo "$TK" | grep -cE '^tk-[0-9a-f]{8}$')" "1"
( cd "$HL" && git add -A && git commit -qm base )
git init -q --bare -b main "$BARE"
( cd "$HL" && git remote add origin "$BARE" && git push -q origin HEAD:main )
git clone -q "$BARE" "$HC"
C peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
C peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1
BASE=$(git -C "$HL" rev-parse HEAD)

# ---------------------------------------------------------------- 1. the repro
head_ "1. the #41 repro: a manifest-only edit is refused"
branch edit
edit "$HC" "$DS" '
m["verification"] = {"tier": "T0"}
m["license"] = "proprietary-internal"
m["availability"] = {"obtainability": "open"}
m["title"] = "readings (official, verified)"
m["links"] = [{"rel": "derives", "id": "wf-00000000"}]'
cpush edit
check "pull --dry-run refuses it" "$(lpull edit --dry-run)" "1"
check "  counted as rejected, not already present" \
  "$(grep -cE 'incoming: 0 new/changed, [0-9]+ already present, 1 rejected' "$W/out.txt")" "1"
check "  naming the changed fields" \
  "$(both | grep -c "edited without an authorised signed republish: availability changed, license changed, link derives:wf-00000000 added with no signed ledger event behind it, title changed, verification.criteria changed, verification.tier changed")" "1"
check "pull refuses it" "$(lpull edit)" "1"
check "  and the lead's manifest is untouched" "$(field "$HL" "$DS" 'm["verification"]["tier"]')" "T3"
check "  and the rejection is quarantined" \
  "$([ "$(grep -c "\"artifact\": \"$DS\"" "$HL/registry/quarantine.log")" -ge 1 ] && echo yes)" "yes"
check "hub check --base fails it" "$(hcheck)" "1"
check "  with the same reason" "$(grep -c "PROBLEM: manifest of already-held $DS edited" "$W/out.txt")" "1"

head_ "1b. single-field edits each fail (criteria, licence)"
branch crit
edit "$HC" "$DS" 'm["verification"]["criteria"] = "machine-verified"'
cpush crit
check "a criteria-only edit is refused by pull" "$(lpull crit --dry-run)" "1"
check "  and by hub check --base" "$(hcheck)" "1"

# ---------------------------------------------------------------- 2. authorised republish
head_ "2. publish --force by the artifact's own publisher is accepted"
branch repub
check "the lead republishes from the contributor's clone (same key)" \
  "$(rc LC publish dataset "$W/r.csv" "readings, corrected title" --force)" "0"
cpush repub
check "hub check --base passes" "$(hcheck)" "0"
check "pull accepts it" "$(lpull repub)" "0"
check "  and says the edit is backed" "$(grep -c 'carry edits backed by a signed republish' "$W/out.txt")" "1"
check "  and the lead holds the new title" "$(field "$HL" "$DS" 'm["title"]')" "readings, corrected title"
check "  with the verification carried forward" "$(field "$HL" "$DS" 'm["verification"]["criteria"]')" "hand-transcribed"
lreset "$BASE"

# ---------------------------------------------------------------- 3. unauthorised republish
head_ "3. publish --force by a key with no authority over the artifact is refused"
branch foreign
check "the contributor republishes the lead's dataset as T0" \
  "$(rc C publish dataset "$W/r.csv" "readings (contrib)" --force --tier T0 --criteria x)" "0"
cpush foreign
check "pull refuses it" "$(lpull foreign --dry-run)" "1"
check "  saying the republish does not authorise it" \
  "$(both | grep -c "does not authorise it: $(echo "$ADDR_C" | tr 'A-Z' 'a-z') (no authority over $DS)")" "1"
check "hub check --base refuses it" "$(hcheck)" "1"

# ---------------------------------------------------------------- 4. legitimate annotations
head_ "4. submit / accept / attest annotations still flow"
branch exchange
check "contributor claims the task" "$(rc C claim "$TK")" "0"
check "contributor submits the lead's dataset (adds fulfills to it)" \
  "$(rc C submit "$TK" "$DS" --force)" "0"
check "  fulfills link written" "$(field "$HC" "$DS" '[l["rel"] for l in m["links"]]')" "['fulfills']"
cpush exchange
check "hub check --base passes the submission" "$(hcheck)" "0"
check "lead pulls the submission" "$(lpull exchange)" "0"
check "  fulfills link landed" "$(field "$HL" "$DS" '[l["rel"] for l in m["links"]]')" "['fulfills']"
check "lead accepts (adds accepted to the task)" "$(rc L accept "$TK" "$DS" --force)" "0"
( cd "$HL" && git add registry && git commit -qm accept && git push -q origin HEAD:main )
( cd "$HC" && git checkout -q main )
check "contributor pulls the acceptance" "$(rc C pull origin)" "0"
check "  accepted link landed" "$(field "$HC" "$TK" '[l["rel"] for l in m.get("links",[])]')" "['accepted']"
BASE2=$(git -C "$HL" rev-parse HEAD)

branch attest
check "contributor attests the lead's T3 dataset" \
  "$(rc C attest "$T3" --observed 2026-09-01T00:00:00Z)" "0"
cpush attest
check "hub check --base passes the attestation" "$(hcheck)" "0"
check "lead pulls it" "$(lpull attest)" "0"
check "  attested_by landed" "$(field "$HL" "$T3" 'm["verification"]["attested_by"]["addr"].lower()')" \
  "$(echo "$ADDR_C" | tr 'A-Z' 'a-z')"
lreset "$BASE2"

# ---------------------------------------------------------------- 5. unbacked annotations
head_ "5. annotations with nothing behind them are refused"
branch forged-link
edit "$HC" "$DS" 'm["links"].append({"rel": "fulfills", "id": "tk-00000000"})'
cpush forged-link
check "a fulfills link with no submit is refused" "$(lpull forged-link --dry-run)" "1"
check "  naming it" "$(both | grep -c 'link fulfills:tk-00000000 added with no signed ledger event')" "1"
check "  and hub check --base refuses it" "$(hcheck)" "1"

branch strip
edit "$HC" "$DS" 'm["links"] = []'
cpush strip
check "removing a link without a republish is refused" "$(lpull strip --dry-run)" "1"
check "  naming it" "$(both | grep -c "link fulfills:$TK removed")" "1"

branch forged-att
edit "$HC" "$T3" '
m["verification"]["attested_by"] = {"addr": "0x0000000000000000000000000000000000000001",
  "sig": "0x00", "statement": {"attests": m["id"], "sha256": m["content"]["sha256"],
  "criteria": "GET /x", "observed": "2026-09-01T00:00:00Z"}}'
cpush forged-att
check "a forged attested_by is refused" "$(lpull forged-att --dry-run)" "1"
check "  naming it" "$(both | grep -c 'attested_by changed without a valid attestation')" "1"

# ---------------------------------------------------------------- 6. known gap
head_ "6. KNOWN GAP (pinned): an edit after a genuine republish rides on it"
branch ride
LC publish dataset "$W/r.csv" "readings v2" --force >/dev/null 2>&1
( cd "$HC" && git add registry store && git commit -qm "genuine republish" )
edit "$HC" "$DS" 'm["verification"] = {"tier": "T0"}'
cpush "ride-along edit"
check "accepted today: the republish signs the content hash, not the manifest" \
  "$(lpull ride --dry-run)" "0"

head_ "housekeeping"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" fsck ) >"$W/out.txt" 2>&1
check "lead fsck clean" "$?" "0"

printf '\n\033[1mtest-manifest-edit: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
