#!/usr/bin/env bash
# Reputation gate — rolling windows and machine-readable peer stats.
# Runs entirely against a throwaway COMMONS_ROOT. Never touches the live registry.
set -uo pipefail

# Hermeticity: never inherit the operator's registry/key/exec settings. A suite that
# behaves differently depending on the invoking shell is measuring the shell.
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-reputation-XXXXXX)"
export COMMONS_AGENT=test-reputation
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W" "$COMMONS_ROOT/registry/artifacts"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

head_ "pure reputation fold"
PYTHONDONTWRITEBYTECODE=1 python3 - "$COMMONS" "$W" <<'PY'
import contextlib, importlib.machinery, importlib.util, io, json, sys

path, work = sys.argv[1:]
loader = importlib.machinery.SourceFileLoader("commons_reputation_test", path)
spec = importlib.util.spec_from_loader(loader.name, loader)
commons = importlib.util.module_from_spec(spec)
loader.exec_module(commons)

a = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
b = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
c = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
bound = commons.parse_ts("2026-07-01T00:00:00Z")
events = [
    {"addr": a, "action": "publish", "ts": "2026-06-30T23:59:59Z"},
    {"addr": a, "action": "republish", "ts": "2026-07-02T00:00:00Z"},
    # Inclusive lower bound: an event exactly at now-duration counts.
    {"addr": a, "action": "claim", "ts": "2026-07-01T00:00:00Z"},
    {"addr": a, "action": "submit", "ts": "2026-07-03T00:00:00Z",
     "_reputation_kind": "origin"},
    {"addr": a, "action": "verify-pass"},
    {"addr": a, "action": "verify-fail", "ts": "not-a-time"},
    {"addr": a, "action": "attest", "ts": "2026-07-04T00:00:00Z"},
    {"addr": b, "action": "submit", "ts": "2026-07-05T00:00:00Z",
     "_reputation_kind": "reference"},
    {"addr": b, "action": "accept", "ts": "2026-07-06T00:00:00Z",
     "_reputation_credit": [a]},
    {"addr": c, "action": "publish", "ts": "2026-07-07T00:00:00Z"},
    {"addr": b, "action": "reject", "ts": "2026-07-08T00:00:00Z",
     "_reputation_credit": [c]},
]
all_time = commons.fold_reputation_events(events)
windowed = commons.fold_reputation_events(events, bound)
json.dump({"all": all_time, "windowed": windowed}, open(work + "/fold.json", "w"),
          sort_keys=True)

with contextlib.redirect_stdout(io.StringIO()) as capture:
    commons.emit_reputation_stats(windowed, "30d", "2026-07-01T00:00:00Z",
                                  False, {"peers": []})
open(work + "/human.txt", "w").write(capture.getvalue())
with contextlib.redirect_stdout(io.StringIO()) as capture:
    commons.emit_reputation_stats(windowed, "30d", "2026-07-01T00:00:00Z",
                                  True, {"peers": []})
open(work + "/stats.json", "w").write(capture.getvalue())

# Shaped view: a flooding peer (D, 20 duplicate-flavored publishes) vs a single
# small contributor (E, 1 publish). Raw reputation rewards D 20x; the shaped
# view must compress that gap sharply because each additional same-category
# event is worth less than the last, and both must stay within the cap.
d_addr = "0xdddddddddddddddddddddddddddddddddddddddd"
e_addr = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
flood_events = [{"addr": d_addr, "action": "publish", "ts": "2026-07-10T00:00:00Z"}
                for _ in range(20)]
flood_events.append({"addr": e_addr, "action": "publish", "ts": "2026-07-10T00:00:00Z"})
flood_raw = commons.fold_reputation_events(flood_events)
flood_shaped = commons.shape_reputation_stats(flood_raw)
json.dump({"raw": flood_raw, "shaped": flood_shaped},
          open(work + "/flood.json", "w"), sort_keys=True)

with contextlib.redirect_stdout(io.StringIO()) as capture:
    commons.emit_reputation_stats(flood_raw, None, None, False, {"peers": []},
                                  shaped=True)
open(work + "/flood_human.txt", "w").write(capture.getvalue())
with contextlib.redirect_stdout(io.StringIO()) as capture:
    commons.emit_reputation_stats(flood_raw, None, None, True, {"peers": []},
                                  shaped=True)
open(work + "/flood_shaped.json", "w").write(capture.getvalue())

# No-flag regression fixture: the exact same windowed stats rendered twice,
# with and without shaped=True, so the shell layer can diff them byte-for-byte
# and prove the unshaped path is untouched by this feature's existence.
with contextlib.redirect_stdout(io.StringIO()) as capture:
    commons.emit_reputation_stats(windowed, "30d", "2026-07-01T00:00:00Z",
                                  False, {"peers": []})
open(work + "/human_regression.txt", "w").write(capture.getvalue())
PY

jget() {
  python3 -c 'import json,sys
v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(v)' "$W/fold.json" "$1"
}

A=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
C=0xcccccccccccccccccccccccccccccccccccccccc
check "window excludes the older event" "$(jget "windowed.$A.published")" "1"
check "all-time retains both events" "$(jget "all.$A.published")" "2"
check "exact lower bound is inclusive" "$(jget "windowed.$A.claims")" "1"
check "missing ts is excluded by a window" "$(jget "windowed.$A.verify_pass")" "0"
check "garbage ts is excluded by a window" "$(jget "windowed.$A.verify_fail")" "0"
check "missing ts counts all-time" "$(jget "all.$A.verify_pass")" "1"
check "garbage ts counts all-time" "$(jget "all.$A.verify_fail")" "1"
check "derivation action mapping is preserved" "$(jget "windowed.$A.derivations")" "1"
check "reference action mapping is preserved" "$(jget "windowed.$B.references")" "1"
check "acceptance credits the submitter" "$(jget "windowed.$A.accepted")" "1"
check "multiple peers remain separated" "$(jget "windowed.$C.published")" "1"
check "submit action mapping is preserved" "$(jget "windowed.$B.submissions")" "1"
check "attest action mapping is preserved" "$(jget "windowed.$A.attested")" "1"
check "rejection credits the submitter" "$(jget "windowed.$C.rejected")" "1"

head_ "shaped view: diminishing returns and caps"
fget() {
  python3 -c 'import json,sys
v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(v)' "$W/flood.json" "$1"
}
D=0xdddddddddddddddddddddddddddddddddddddddd
E=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
check "raw counts reward flooding linearly" "$(fget "raw.$D.published")" "20"
check "raw single contributor unaffected" "$(fget "raw.$E.published")" "1"
check "shaped flooder scores sublinearly (not 20x the single contributor)" \
  "$(python3 -c 'import json;d=json.load(open("'"$W"'/flood.json"));fl=d["shaped"]["'"$D"'"]["published"];one=d["shaped"]["'"$E"'"]["published"];print(fl < 20*one)')" \
  "True"
check "shaped view never exceeds the per-category cap" \
  "$(python3 -c 'import json;d=json.load(open("'"$W"'/flood.json"));print(d["shaped"]["'"$D"'"]["published"] <= 50)')" "True"
check "shaped never scores below zero" \
  "$(python3 -c 'import json;d=json.load(open("'"$W"'/flood.json"));print(all(v>=0 for v in d["shaped"]["'"$D"'"].values()))')" "True"
check "shaped single event equals the rate constant (ceil(10/sqrt(1)))" "$(fget "shaped.$E.published")" "10"
check "shaped human header names the shaped mode" \
  "$(grep -c '^peer stats (shaped: diminishing returns per category, capped)$' "$W/flood_human.txt")" "1"
check "shaped JSON marks shaped:true" \
  "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("shaped"))' "$W/flood_shaped.json")" "True"
check "shaped JSON peers carry shaped, not raw, counts" \
  "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["peers"]["'"$D"'"]["published"] != 20)' "$W/flood_shaped.json")" "True"

head_ "no-flag regression: default output is byte-identical without --shaped"
check "unshaped emit_reputation_stats output is unaffected by the shaped feature existing" \
  "$(diff -q "$W/human.txt" "$W/human_regression.txt" >/dev/null 2>&1 && echo same)" "same"

head_ "JSON and CLI surface"
check "JSON shape carries window and bound"   "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print("%s %s" % (d["window"],d["bound"]))' "$W/stats.json")"   "30d 2026-07-01T00:00:00Z"
check "JSON address keys are lowercase"   "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(all(k==k.lower() for k in d["peers"]))' "$W/stats.json")"   "True"
# Addresses are namespaced under "peers" rather than merged into the top level:
# a peer keyed "window" must not be able to shadow the metadata.
check "JSON namespaces peers away from metadata"   "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(sorted(d)==["bound","peers","window"])' "$W/stats.json")"   "True"
check "JSON counts match human columns"   "$(python3 - "$W/stats.json" "$W/human.txt" "$A" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))["peers"]
row = next(line.split() for line in open(sys.argv[2]) if line.startswith(sys.argv[3]))
r = data[sys.argv[3]]
print(row[2:] == [str(r[k]) for k in ("published", "derivations", "references",
                                      "accepted", "rejected", "verify_pass")])
PY
)" "True"
check "window is printed in the human header"   "$(grep -c '^peer stats (window: last 30d)$' "$W/human.txt")" "1"
check "empty all-time JSON uses null metadata"   "$(c peer stats --json | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d=={"window":None,"bound":None,"peers":{}})')"   "True"
check "CLI accepts a duration and prints its header"   "$(c peer stats --window 30d | grep -c '^peer stats (window: last 30d)$')" "1"
check "CLI rejects a unitless duration" "$(rc c peer stats --window 30)" "1"
check "CLI --shaped prints the shaped header on empty stats" \
  "$(c peer stats --shaped | grep -c '^peer stats (shaped: diminishing returns per category, capped)$')" "1"
check "CLI --shaped --json marks shaped:true even with no activity" \
  "$(c peer stats --shaped --json | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("shaped"))')" "True"
check "CLI without --shaped omits the shaped key entirely (no-flag regression)" \
  "$(c peer stats --json | python3 -c 'import json,sys;d=json.load(sys.stdin);print("shaped" in d)')" "False"
check "CLI without --shaped keeps the pre-existing exact JSON shape (window/bound/peers only)" \
  "$(c peer stats --json | python3 -c 'import json,sys;d=json.load(sys.stdin);print(sorted(d)==["bound","peers","window"])')" "True"

printf '\n\033[1mtest-reputation: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
