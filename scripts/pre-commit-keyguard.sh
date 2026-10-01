#!/usr/bin/env bash
# Refuse to commit anything shaped like a private key.
#
# Written after a test fixture's key literal got mangled during an edit and wrote a
# real 32-byte secp256k1 key to the repo root, where `git add -A` staged it. It was
# caught by inspection before committing — which is exactly the kind of catch that
# should not depend on someone looking carefully at the right moment.
#
# Install:  ln -sf ../../scripts/pre-commit-keyguard.sh .git/hooks/pre-commit
set -uo pipefail

fail=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  # Only small files can be bare keys; skip anything large to stay fast.
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -gt 4096 ] && continue
  if python3 - "$f" <<'PY'
import re, sys
try:
    d = open(sys.argv[1], "r", errors="replace").read()
except Exception:
    sys.exit(1)
# A bare private key as whole-file content, or an obvious PEM block.
# Assembled at runtime so this detector does not match its own source — the first
# version blocked itself, which is funny once and a broken hook thereafter.
DASHES = "-" * 5
pem = re.compile(DASHES + r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY" + DASHES)
if re.fullmatch(r"\s*0x?[0-9a-fA-F]{64}\s*", d) or pem.search(d):
    sys.exit(0)
sys.exit(1)
PY
  then
    echo "BLOCKED: $f looks like a private key" >&2
    fail=1
  fi
done < <(git diff --cached --name-only --diff-filter=ACM)

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "Refusing the commit. Keys belong outside the repo (COMMONS_SIGNING_KEY is a" >&2
  echo "path for exactly this reason). If this is a deliberate fixture, it still" >&2
  echo "should not be committed — generate it into a temp dir at test time." >&2
  exit 1
fi
