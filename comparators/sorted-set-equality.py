#!/usr/bin/env python3
"""sorted-set-equality — T1 comparator: line-set equality (order-insensitive).

Contract (research-commons comparator ABI):
    <comparator> <expected-file> <actual-file>   → exit 0 equivalent, 1 not

For outputs whose *content* is deterministic but whose *line order* is not
(parallel writers, dict iteration, `find` ordering). Compares the multiset of
lines by default.

    env IGNORE_BLANK   "1" (default) drop blank lines
    env STRIP          "1" (default) strip trailing whitespace per line
    env IGNORE_PREFIX  drop lines starting with this prefix (e.g. "#")
    env AS_SET         "1" compare as a set (collapse duplicates); default
                       "0" = multiset (duplicate counts must match)

Deterministic, stdlib only. Self-test: `sorted-set-equality.py --self-test`.
"""
import collections, os, sys

MAX_REPORT = 20


def _opts(env=None):
    e = env if env is not None else os.environ
    return {
        "ignore_blank": e.get("IGNORE_BLANK", "1") == "1",
        "strip": e.get("STRIP", "1") == "1",
        "ignore_prefix": e.get("IGNORE_PREFIX", ""),
        "as_set": e.get("AS_SET", "0") == "1",
    }


def normalize(text, o):
    out = []
    for line in text.splitlines():
        if o["strip"]: line = line.rstrip()
        if o["ignore_blank"] and not line.strip(): continue
        if o["ignore_prefix"] and line.startswith(o["ignore_prefix"]): continue
        out.append(line)
    return out


def compare_text(exp_text, act_text, o):
    """Returns list of human-readable differences (empty == equivalent)."""
    exp, act = normalize(exp_text, o), normalize(act_text, o)
    if o["as_set"]:
        se, sa = set(exp), set(act)
        diffs = ["- missing: %r" % l for l in sorted(se - sa)]
        diffs += ["+ unexpected: %r" % l for l in sorted(sa - se)]
        return diffs
    ce, ca = collections.Counter(exp), collections.Counter(act)
    diffs = []
    for line in sorted(set(ce) | set(ca)):
        d = ca[line] - ce[line]
        if d < 0: diffs.append("- missing ×%d: %r" % (-d, line))
        elif d > 0: diffs.append("+ unexpected ×%d: %r" % (d, line))
    return diffs


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f: return f.read()
    except OSError as e:
        sys.exit("error: cannot read %s: %s" % (path, e))


def self_test():
    base = _opts({})
    cases = [
        ("same order", "a\nb\nc\n", "a\nb\nc\n", base, True),
        ("shuffled", "a\nb\nc\n", "c\na\nb\n", base, True),
        ("missing line", "a\nb\nc\n", "a\nb\n", base, False),
        ("extra line", "a\nb\n", "a\nb\nc\n", base, False),
        ("blank lines ignored", "a\n\nb\n", "b\na\n\n\n", base, True),
        ("trailing ws stripped", "a  \nb\n", "a\nb\n", base, True),
        ("dup counts matter", "a\na\nb\n", "a\nb\n", base, False),
        ("dup ok as set", "a\na\nb\n", "a\nb\n", _opts({"AS_SET": "1"}), True),
        ("comments ignored", "# hdr\na\n", "a\n# other\n", _opts({"IGNORE_PREFIX": "#"}), True),
        ("no trailing newline", "a\nb", "b\na\n", base, True),
        ("empty both", "", "\n\n", base, True),
        ("case sensitive", "a\n", "A\n", base, False),
        ("strip off keeps ws", "a  \n", "a\n", _opts({"STRIP": "0"}), False),
    ]
    bad = 0
    for name, e, a, o, want in cases:
        got = not compare_text(e, a, o)
        if got != want: bad += 1
        print("%s %s (want %s, got %s)" % ("ok  " if got == want else "FAIL", name, want, got))
    print("self-test: %s" % ("PASS" if bad == 0 else "%d FAILURE(S)" % bad))
    return 1 if bad else 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 3:
        sys.exit("usage: sorted-set-equality <expected> <actual>   "
                 "(env IGNORE_BLANK, STRIP, IGNORE_PREFIX, AS_SET)")
    o = _opts()
    diffs = compare_text(_read(argv[1]), _read(argv[2]), o)
    if not diffs:
        print("equivalent as %s of lines" % ("set" if o["as_set"] else "multiset"))
        return 0
    for d in diffs[:MAX_REPORT]: print(d, file=sys.stderr)
    if len(diffs) > MAX_REPORT:
        print("… %d more difference(s)" % (len(diffs) - MAX_REPORT), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
