#!/usr/bin/env python3
"""json-numeric-epsilon — T1 comparator: JSON equality with float tolerance.

Contract (research-commons comparator ABI):
    <comparator> <expected-file> <actual-file>   → exit 0 equivalent, 1 not
    env EPSILON   relative/absolute tolerance for floats (default 1e-9)
    env NAN_EQUAL "1" treats NaN == NaN (default: NaN never equals anything)

Structure must match exactly (same keys, same list lengths, same types modulo
int/float); only numeric *leaves* are compared with tolerance. Differences are
reported on stderr as JSON paths so a failing verify says where it diverged.

Deterministic, stdlib only. Self-test: `json-numeric-epsilon.py --self-test`.
"""
import json, math, os, sys

MAX_REPORT = 20


def _tol():
    try:
        eps = float(os.environ.get("EPSILON", "1e-9"))
    except ValueError:
        sys.exit("error: EPSILON is not a number: %r" % os.environ.get("EPSILON"))
    if eps < 0: sys.exit("error: EPSILON must be >= 0")
    return eps


def _num_equal(a, b, eps, nan_equal):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    fa, fb = float(a), float(b)
    if math.isnan(fa) or math.isnan(fb):
        return nan_equal and math.isnan(fa) and math.isnan(fb)
    if math.isinf(fa) or math.isinf(fb):
        return fa == fb
    diff = abs(fa - fb)
    if diff <= eps: return True
    scale = max(abs(fa), abs(fb))
    return diff <= eps * scale


def compare(exp, act, eps, nan_equal=False, path="$", diffs=None):
    if diffs is None: diffs = []
    if len(diffs) >= MAX_REPORT: return diffs
    if isinstance(exp, bool) or isinstance(act, bool):
        if exp is not act: diffs.append("%s: %r != %r" % (path, exp, act))
    elif isinstance(exp, (int, float)) and isinstance(act, (int, float)):
        if not _num_equal(exp, act, eps, nan_equal):
            diffs.append("%s: %r != %r (delta %g > eps %g)"
                         % (path, exp, act, abs(float(exp) - float(act)), eps))
    elif isinstance(exp, dict) and isinstance(act, dict):
        for k in sorted(set(exp) | set(act)):
            if k not in exp: diffs.append("%s.%s: unexpected key" % (path, k))
            elif k not in act: diffs.append("%s.%s: missing key" % (path, k))
            else: compare(exp[k], act[k], eps, nan_equal, "%s.%s" % (path, k), diffs)
    elif isinstance(exp, list) and isinstance(act, list):
        if len(exp) != len(act):
            diffs.append("%s: length %d != %d" % (path, len(exp), len(act)))
        else:
            for i, (e, a) in enumerate(zip(exp, act)):
                compare(e, a, eps, nan_equal, "%s[%d]" % (path, i), diffs)
    elif type(exp) is not type(act):
        diffs.append("%s: type %s != %s" % (path, type(exp).__name__, type(act).__name__))
    elif exp != act:
        diffs.append("%s: %r != %r" % (path, exp, act))
    return diffs


def _load(path):
    try:
        with open(path) as f: return json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("error: cannot read JSON from %s: %s" % (path, e))


def self_test():
    eps = 1e-9
    cases = [
        ("identical", {"a": 1.0}, {"a": 1.0}, True),
        ("last-ulp jitter", {"a": 0.1 + 0.2}, {"a": 0.30000000000000004}, True),
        ("within eps", {"a": 1.0}, {"a": 1.0 + 1e-12}, True),
        ("relative scale", {"a": 1e9}, {"a": 1e9 + 0.5}, True),
        ("beyond eps", {"a": 1.0}, {"a": 1.001}, False),
        ("nested ok", {"x": [{"y": 2.0}]}, {"x": [{"y": 2.0 + 1e-15}]}, True),
        ("nested bad", {"x": [{"y": 2.0}]}, {"x": [{"y": 3.0}]}, False),
        ("missing key", {"a": 1, "b": 2}, {"a": 1}, False),
        ("extra key", {"a": 1}, {"a": 1, "b": 2}, False),
        ("list length", [1, 2], [1, 2, 3], False),
        ("string equal", {"s": "x"}, {"s": "x"}, True),
        ("string differ", {"s": "x"}, {"s": "y"}, False),
        ("bool vs int", {"b": True}, {"b": 1}, False),
        ("int vs float same", {"n": 3}, {"n": 3.0}, True),
        ("null equal", {"n": None}, {"n": None}, True),
        ("nan never equal", {"n": float("nan")}, {"n": float("nan")}, False),
    ]
    bad = 0
    for name, e, a, want in cases:
        got = not compare(e, a, eps)
        flag = "ok  " if got == want else "FAIL"
        if got != want: bad += 1
        print("%s %s (want %s, got %s)" % (flag, name, want, got))
    # infinity + NAN_EQUAL behaviour
    got = not compare({"n": float("inf")}, {"n": float("inf")}, eps)
    if not got: bad += 1
    print("%s inf equals inf" % ("ok  " if got else "FAIL"))
    got = not compare({"n": float("nan")}, {"n": float("nan")}, eps, nan_equal=True)
    if not got: bad += 1
    print("%s NAN_EQUAL=1 makes nan equal" % ("ok  " if got else "FAIL"))
    print("self-test: %s" % ("PASS" if bad == 0 else "%d FAILURE(S)" % bad))
    return 1 if bad else 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 3:
        sys.exit("usage: json-numeric-epsilon <expected.json> <actual.json>   (env EPSILON, NAN_EQUAL)")
    eps = _tol()
    nan_equal = os.environ.get("NAN_EQUAL", "") == "1"
    diffs = compare(_load(argv[1]), _load(argv[2]), eps, nan_equal)
    if not diffs:
        print("equivalent under EPSILON=%g" % eps)
        return 0
    for d in diffs[:MAX_REPORT]: print(d, file=sys.stderr)
    if len(diffs) >= MAX_REPORT: print("… (truncated)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
