#!/usr/bin/env bash
# research-commons anchor cron — stamp ledger heads, then upgrade pending proofs.
#
# NO inference: pure local hashing + an OTS calendar call. Plain host crontab: wrapping
# this in an agent-scheduled job would burn a model call for nothing.
#
# Install (every 6h, staggered off the hour); both variables are required:
#   17 */6 * * * COMMONS_SIGNING_KEY=$HOME/.commons/signing.key COMMONS_AGENT=<handle> /path/to/research-commons/scripts/anchor-cron.sh
#
# ⚠️ PATH: `ots` is a pipx install in ~/.local/bin, which a bare crontab PATH does
# NOT include. Export it BEFORE any `command -v` check — a stale/absent binary
# silently no-ops otherwise (we have lost days to exactly this).
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.local/share/pipx/venvs/opentimestamps-client/bin:$PATH"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMONS="$REPO/bin/commons"
LOG_DIR="$REPO/logs"
LOG="$LOG_DIR/anchor-cron.log"
mkdir -p "$LOG_DIR"

# Signing key: anchors are ledger events, so they get signed like everything else.
# Use a dedicated commons identity, never a payment-wallet key.
: "${COMMONS_SIGNING_KEY:?set COMMONS_SIGNING_KEY}"
export COMMONS_SIGNING_KEY
: "${COMMONS_AGENT:?set COMMONS_AGENT (the ledger attribution name)}"
export COMMONS_AGENT

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }

if ! command -v ots >/dev/null 2>&1; then
  log "SKIP: no ots on PATH (pipx install opentimestamps-client); PATH=$PATH"
  exit 0
fi

# 1. Upgrade proofs pending from earlier runs. Do this FIRST: if the new stamp
#    fails (calendar unreachable), yesterday's proof still gets promoted.
if out=$("$COMMONS" anchor-upgrade 2>&1); then
  log "upgrade: $(echo "$out" | tail -1)"
else
  log "upgrade FAILED: $(echo "$out" | tail -1)"
fi

# 2. Stamp the current heads.
if out=$("$COMMONS" anchor 2>&1); then
  log "anchor: $(echo "$out" | grep -E '^root ' || echo "$out" | tail -1)"
else
  log "anchor FAILED: $(echo "$out" | tail -1)"
  exit 1
fi

# 3. Consistency check — a root that no longer re-derives means the ledger moved
#    under us, which is exactly what anchoring exists to catch.
if out=$("$COMMONS" anchor-verify 2>&1); then
  log "verify: $(echo "$out" | tail -1)"
else
  log "VERIFY FAILED (root mismatch): $(echo "$out" | tail -3 | tr '\n' ' ')"
  exit 1
fi
