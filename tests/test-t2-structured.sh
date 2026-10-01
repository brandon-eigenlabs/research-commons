#!/usr/bin/env bash
# T2 structured judgements (2026-09-15).
#
# The defect this closes: a T2 diversity quorum had NO reachable success state.
# Independent judges agreeing in different prose read DIVERGENT (bytes differ);
# byte-identical judges deduped into one artifact and stalled at 1/k. Both branches
# of "are the bytes equal" were exhaustive, so k>=2 on T2 was unsatisfiable.
#
# Fix: a T2 task may declare verification.criteria_list [{id,text}]; a T2 result may
# carry judgement {id: pass|fail|NA}; settle groups by the VERDICT VECTOR, not the
# content hash. Independence is still decided on the prose (a copied review with a
# retyped vector is still a copy). This suite proves each half and the guards.
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Probe with a throwaway key: this checks viem is installed, not that the host has a key.
_PROBEKEY="$(mktemp -t commons-probe-XXXXXX)"
python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_PROBEKEY"
if ! MESSAGE=probe COMMONS_SIGNING_KEY="$_PROBEKEY" node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  rm -f "$_PROBEKEY"
  echo "test-t2-structured: signer not functional"; exit 1
fi
rm -f "$_PROBEKEY"

LAB="$(mktemp -d -t commons-t2s-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/reg"; export COMMONS_AGENT=test-t2s
mkdir -p "$COMMONS_ROOT/registry" "$LAB/w"
cp "$REPO/registry/exec-policy.example.json" "$COMMONS_ROOT/registry/exec-policy.json"
W="$LAB/w"

mkkey() { python3 -c "import secrets;open('$1','w').write('0x'+secrets.token_hex(32))"; chmod 600 "$1"; }
BKEY="$LAB/ben.key"; AKEY="$LAB/a.key"; CKEY="$LAB/c.key"; DKEY="$LAB/d.key"
mkkey "$BKEY"; mkkey "$AKEY"; mkkey "$CKEY"; mkkey "$DKEY"
ben() { COMMONS_SIGNING_KEY="$BKEY" "$COMMONS" "$@"; }
ja()  { COMMONS_SIGNING_KEY="$AKEY" COMMONS_AGENT=judge-a "$COMMONS" "$@"; }
jc()  { COMMONS_SIGNING_KEY="$CKEY" COMMONS_AGENT=judge-c "$COMMONS" "$@"; }
jd()  { COMMONS_SIGNING_KEY="$DKEY" COMMONS_AGENT=judge-d "$COMMONS" "$@"; }
rc()  { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both(){ cat "$W/out.txt" "$W/err.txt"; }

BEN=$(ben peer whoami | head -1); A=$(ja peer whoami | head -1)
C=$(jc peer whoami | head -1);    D=$(jd peer whoami | head -1)
for p in "$BEN:test-t2s" "$A:judge-a" "$C:judge-c" "$D:judge-d"; do
  ben peer add "${p%%:*}" --agent-id "${p##*:}" --trust full >/dev/null
done

printf 'subject under review\n' > "$W/subject.md"
SUBJ=$(ben publish report "$W/subject.md" "thing to be judged" 2>/dev/null)

mktask() {  # mktask <outfile> <json-overrides>
  python3 - "$1" "$SUBJ" "$BEN" "$2" <<'PY'
import json, sys
out, subj, ben, over = sys.argv[1:5]
spec = {"objective": "Review the subject against the rubric", "priority": 2,
        "expires": "2099-01-01T00:00:00Z", "inputs": [{"id": subj}],
        "execution": {"brief": "read the subject, judge each criterion"},
        "verification": {"tier": "T2",
                         "criteria": "cites artifacts; numbers trace; no unsupported claims",
                         "criteria_list": [
                             {"id": "cites", "text": "every claim cites an artifact id"},
                             {"id": "traces", "text": "every number traces to a cited artifact"},
                             {"id": "scope", "text": "no claim exceeds the cited evidence"}]},
        "max_claims": 3, "diversity_quorum": {"k": 2, "distinct_families": 0},
        "beneficiary": {"agent": "test-t2s", "addr": ben}}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}

head_ "lint: enumerated rubric"
mktask "$W/t-ok.json" '{}'
TK=$(ben publish task "$W/t-ok.json" "Structured T2 review" 2>/dev/null)
check "T2 task with criteria_list + k=2 publishes" "$(echo "$TK" | grep -c '^tk-')" "1"

mktask "$W/t-nolist.json" '{"verification": {"tier": "T2", "criteria": "prose only"}}'
check "T2 k=2 WITHOUT criteria_list is refused" "$(rc ben publish task "$W/t-nolist.json" x)" "1"
check "  refusal explains why" "$(both | grep -c 'must declare verification.criteria_list')" "1"

mktask "$W/t-k1.json" '{"verification": {"tier": "T2", "criteria": "prose only"}, "diversity_quorum": null}'
check "T2 prose-only with no quorum still publishes (nothing invalidated)" \
  "$(ben publish task "$W/t-k1.json" k1 2>/dev/null | grep -c '^tk-')" "1"

mktask "$W/t-dup.json" '{"verification": {"tier": "T2", "criteria": "x", "criteria_list": [{"id": "a", "text": "one"}, {"id": "a", "text": "two"}]}}'
check "duplicate criterion id refused" "$(rc ben publish task "$W/t-dup.json" x)" "1"
check "  names the duplicate" "$(both | grep -c 'duplicate criterion id')" "1"

mktask "$W/t-badid.json" '{"verification": {"tier": "T2", "criteria": "x", "criteria_list": [{"id": "1 bad id", "text": "one"}]}}'
check "malformed criterion id refused" "$(rc ben publish task "$W/t-badid.json" x)" "1"

mktask "$W/t-ped.json" '{"verification": {"tier": "T2", "criteria": "x", "criteria_list": [{"id": "a", "text": "must be written by Claude"}]}}'
check "pedigree inside criteria_list refused" "$(rc ben publish task "$W/t-ped.json" x)" "1"
check "  same rubric-judges-output rule" "$(both | grep -c 'never who produced it')" "1"

mktask "$W/t-t0list.json" '{"verification": {"tier": "T0", "criteria": "bytes", "criteria_list": [{"id": "a", "text": "one"}]}, "execution": {"workflow": "wf-00000000"}}'
check "criteria_list on a machine tier refused" "$(rc ben publish task "$W/t-t0list.json" x)" "1"
check "  says machine tiers compare bytes" "$(both | grep -c 'machine tiers compare bytes')" "1"

head_ "task surfaces show the rubric"
check "status lists each criterion" "$(ben status "$TK" | grep -cE '^    (cites|traces|scope) ')" "3"
check "queue --json carries criteria_list" \
  "$(ben queue --json | python3 -c "import json,sys; r=[x for x in json.load(sys.stdin) if x['id']=='$TK'][0]; print(len(r['criteria_list']))")" "3"

head_ "publish --judgement"
printf 'Review A: cites ok, numbers trace, one claim overreaches.\n' > "$W/ra.md"
printf 'Review C: solid citations and tracing; scope criterion fails on para 3.\n' > "$W/rc.md"
printf 'Review D: everything passes.\n' > "$W/rd.md"
check "--judgement on a non-T2 artifact refused" \
  "$(rc ja publish report "$W/ra.md" x --judgement cites=pass)" "1"
check "--judgement with bad verdict refused" \
  "$(rc ja publish report "$W/ra.md" x --tier T2 --criteria r --judgement cites=maybe)" "1"
check "  names the closed vocabulary" "$(both | grep -c 'pass|fail|NA')" "1"
check "--judgement malformed pair refused" \
  "$(rc ja publish report "$W/ra.md" x --tier T2 --criteria r --judgement cites)" "1"
check "--judgement repeated id refused" \
  "$(rc ja publish report "$W/ra.md" x --tier T2 --criteria r --judgement cites=pass --judgement cites=fail)" "1"

RA=$(ja publish report "$W/ra.md" "review A" --tier T2 --criteria "rubric of $TK" \
       --judgement cites=pass --judgement traces=pass --judgement scope=fail 2>/dev/null)
check "judged result publishes" "$(echo "$RA" | grep -c '^rp-')" "1"
check "manifest carries the judgement block" \
  "$(ja get "$RA" | python3 -c "import json,sys; print(json.load(sys.stdin)['judgement']['scope'])")" "fail"

head_ "submit: judgement cross-checked against the task rubric"
ja claim "$TK" >/dev/null 2>&1
printf 'Review with wrong keys\n' > "$W/rbad.md"
RBAD=$(ja publish report "$W/rbad.md" "bad keys" --tier T2 --criteria r \
         --judgement cites=pass --judgement bogus=fail 2>/dev/null)
check "judgement naming undeclared criterion refused at submit" "$(rc ja submit "$TK" "$RBAD")" "1"
check "  names the extra criterion" "$(both | grep -c 'bogus')" "1"
check "  names the missing ones" "$(both | grep -c 'missing verdicts')" "1"
printf 'Prose-only review\n' > "$W/rprose.md"
RPROSE=$(ja publish report "$W/rprose.md" "prose only" --tier T2 --criteria r 2>/dev/null)
check "prose-only result on a structured task refused at submit" "$(rc ja submit "$TK" "$RPROSE")" "1"
check "  tells the contributor how to fix it" "$(both | grep -c -- '--judgement ID=pass|fail|NA')" "1"
check "  lists the criterion ids" "$(both | grep -c 'cites, traces, scope')" "1"
check "well-formed judged result submits" "$(rc ja submit "$TK" "$RA")" "0"
check "  counts as independent derivation (origin)" "$(both | grep -c 'independent derivation')" "1"

head_ "THE FIX: different prose, same verdicts = agreement"
jc claim "$TK" >/dev/null 2>&1
RC=$(jc publish report "$W/rc.md" "review C" --tier T2 --criteria "rubric of $TK" \
       --judgement scope=fail --judgement cites=pass --judgement traces=pass 2>/dev/null)
check "second review is a distinct artifact (different bytes)" "$([ "$RA" != "$RC" ] && echo yes)" "yes"
jc submit "$TK" "$RC" >/dev/null 2>&1
check "status: NOT divergent" "$(ben status "$TK" | grep -c 'DIVERGENT')" "0"
check "status: 2 independent judgements agree" \
  "$(ben status "$TK" | grep -c 'congruence : 2 independent judgement(s) agree')" "1"
check "status: verdict order is the rubric's, not the typing order" \
  "$(ben status "$TK" | grep -c 'cites=pass,traces=pass,scope=fail')" "1"
check "status: criterion table rendered (one row per criterion)" "$(ben status "$TK" | grep -cE '^    (cites|traces|scope) +(pass|fail)×2$')" "3"
check "status: no criterion SPLIT" "$(ben status "$TK" | grep -c 'SPLIT')" "0"
check "settle --dry-run: settleable (exit 0)" "$(rc ben settle "$TK" --dry-run)" "0"
check "  names the agreed vector" "$(both | grep -c 'verdict vector cites=pass,traces=pass,scope=fail')" "1"
check "  says agreement is on verdicts, prose is evidence" "$(both | grep -c 'prose is the evidence')" "1"
check "settle for real: accepted by quorum" "$(rc ben settle "$TK")" "0"
check "ledger records settlement=verdict-quorum with the vector" \
  "$(grep -h '"action": "accept"' "$COMMONS_ROOT"/registry/ledger/*.jsonl | grep -c '"settlement": "verdict-quorum".*"verdict_vector": "cites=pass,traces=pass,scope=fail"\|"verdict_vector": "cites=pass,traces=pass,scope=fail".*"settlement": "verdict-quorum"')" "1"
check "task state accepted" "$(ben status "$TK" | grep -c 'state      : accepted')" "1"

head_ "THE OTHER HALF: same-ish prose, different verdicts = divergence, located"
mktask "$W/t-div.json" '{"objective": "divergence probe"}'
TKD=$(ben publish task "$W/t-div.json" "Structured T2 divergence" 2>/dev/null)
printf 'Review D1 of the divergence probe\n' > "$W/rd1.md"
printf 'Review D2 of the divergence probe\n' > "$W/rd2.md"
ja claim "$TKD" >/dev/null 2>&1; jd claim "$TKD" >/dev/null 2>&1
RD1=$(ja publish report "$W/rd1.md" "D1" --tier T2 --criteria r --judgement cites=pass --judgement traces=pass --judgement scope=fail 2>/dev/null)
RD2=$(jd publish report "$W/rd2.md" "D2" --tier T2 --criteria r --judgement cites=pass --judgement traces=fail --judgement scope=pass 2>/dev/null)
ja submit "$TKD" "$RD1" >/dev/null 2>&1; jd submit "$TKD" "$RD2" >/dev/null 2>&1
check "status: DIVERGENT on verdict vectors" "$(ben status "$TKD" | grep -c 'DIVERGENT — 2 distinct verdict vectors')" "1"
check "status: split criteria marked" "$(ben status "$TKD" | grep -c '← SPLIT')" "2"
check "status: agreed criterion NOT marked" "$(ben status "$TKD" | grep -E '^    cites ' | grep -c 'SPLIT')" "0"
check "settle: refuses (exit 1, same contract as T0)" "$(rc ben settle "$TKD" --dry-run)" "1"
check "  names the split criteria" "$(both | grep -c 'reviewers split on criteria: traces, scope')" "1"
check "  does NOT say nondeterministic pipeline" "$(both | grep -ci 'not deterministic')" "0"
check "beneficiary can still accept by hand" "$(rc ben accept "$TKD" "$RD1")" "0"

head_ "independence still rides on the prose, not the vector"
mktask "$W/t-copy.json" '{"objective": "copy probe"}'
TKC=$(ben publish task "$W/t-copy.json" "Structured T2 copy" 2>/dev/null)
printf 'Original review text for the copy probe\n' > "$W/orig.md"
ja claim "$TKC" >/dev/null 2>&1; jd claim "$TKC" >/dev/null 2>&1
RO=$(ja publish report "$W/orig.md" "orig" --tier T2 --criteria r --judgement cites=pass --judgement traces=pass --judgement scope=pass 2>/dev/null)
ja submit "$TKC" "$RO" >/dev/null 2>&1
# D copies A's bytes verbatim: publish dedups to the same id, so D can only submit A's id.
RCOPY=$(jd publish report "$W/orig.md" "copy" --tier T2 --criteria r --judgement cites=pass --judgement traces=pass --judgement scope=pass 2>/dev/null | grep -oE 'rp-[0-9a-f]{8}' | head -1)
check "copied bytes dedup to the original id" "$([ "$RCOPY" = "$RO" ] && echo yes)" "yes"
jd submit "$TKC" "$RO" >"$W/out.txt" 2>&1
check "copy submission is a concurring reference" "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "settle stalls at 1/2 — vector agreement is not a second derivation" "$(rc ben settle "$TKC" --dry-run)" "3"
check "  reports 1/2" "$(both | grep -c '1/2 independent derivation')" "1"

head_ "back-compat: prose-only T2 (no criteria_list) unchanged"
mktask "$W/t-legacy.json" '{"verification": {"tier": "T2", "criteria": "legacy prose rubric"}, "diversity_quorum": null, "max_claims": 1}'
TKL=$(ben publish task "$W/t-legacy.json" "legacy T2" 2>/dev/null)
ja claim "$TKL" >/dev/null 2>&1
printf 'legacy review\n' > "$W/leg.md"
RL=$(ja publish report "$W/leg.md" "legacy" --tier T2 --criteria r 2>/dev/null)
check "prose-only submit still works (no rubric to check against)" "$(rc ja submit "$TKL" "$RL")" "0"
check "no rubric line on a legacy task" "$(ben status "$TKL" | grep -c 'rubric     :')" "0"
check "settle without quorum still says accepted by review" "$(rc ben settle "$TKL")" "1"
check "  wording unchanged" "$(both | grep -c 'accepted by review, not by counting')" "1"

head_ "queue --tips-only hides superseded tasks (read-only disambiguation)"
mktask "$W/t-old.json" '{"objective": "old task"}'
TKO=$(ben publish task "$W/t-old.json" "old" 2>/dev/null)
mktask "$W/t-new.json" '{"objective": "new task"}'
TKN=$(ben publish task "$W/t-new.json" "new" --link "supersedes:$TKO" 2>/dev/null)
check "default queue shows both" "$(ben queue 2>/dev/null | grep -cE "^($TKO|$TKN) ")" "2"
check "--tips-only hides the superseded one" "$(ben queue --tips-only 2>/dev/null | grep -cE "^($TKO|$TKN) ")" "1"
check "  and it is the old one that is hidden" "$(ben queue --tips-only 2>/dev/null | grep -c "^$TKO ")" "0"
check "  footer counts the hidden row" "$(ben queue --tips-only 2>&1 >/dev/null | grep -c 'superseded hidden')" "1"

printf '\n%d ok, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
