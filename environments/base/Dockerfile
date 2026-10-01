# research-commons base execution environment
#
# Build recipe for `research-commons-sandbox:base`, the default image in
# registry/exec-policy.example.json (and the tool's built-in fallback policy). Nobody
# has to pull an image from us: everyone builds the default locally from this file, and
# without a recipe a tag is an unverifiable claim and "reproduce this T0 artifact" is
# unanswerable off the publisher's machine.
#
# Contract this image satisfies: ../CONTRACT.md. ANY image meeting that contract can run
# commons workflows; this one is the default, not a requirement.
#
#   docker build -t research-commons-sandbox:base environments/base/
#
# ── Why snapshot.debian.org ────────────────────────────────────────────────────────
# The first draft of this file pinned exact package versions against the normal Debian
# mirrors. It failed to build the same day it was written:
#
#   E: Version '5.2.15-2+b10' for 'bash' was not found
#   E: Version '7.88.1-10+deb12u14' for 'curl' was not found
#
# Nothing was wrong with the pins — the mirrors had simply rolled 12.13 → 12.15 and
# garbage-collected the old versions. That is the normal state of affairs, not an
# unlucky day, and it is exactly why "pin the versions" is not by itself a reproducible
# build: the pins are only as durable as the archive behind them.
#
# So the archive is pinned too. snapshot.debian.org serves the archive AS OF A TIMESTAMP,
# which makes the package set a function of SNAPSHOT rather than of when you happen to
# build. Verified 2026-08-02: at 20260513T000000Z this resolves 6 of the 7 packages to
# byte-identical versions with the image this recipe was first written to reproduce
# (built earlier from the live mirrors).
#
# ── What is and isn't promised ─────────────────────────────────────────────────────
#   same package versions   → yes, this is what the snapshot pin buys
#   same image digest       → NO. Two builds differ in digest (timestamps, layer
#                             metadata); a digest is only shared by pulling one image.
#   environment-independent → the property actually worth having: declare T1 with a
#                             comparator and stop depending on the userland at all.
#
# A rebuild producing a different digest than ours is EXPECTED and is not a verification
# failure. `commons verify` reports ENV-MISMATCH (exit 5), never FAIL (1), for this case.
# See ../CONTRACT.md §"When digests differ".
#
# ── Base pin ───────────────────────────────────────────────────────────────────────
# Pinned by digest: `debian:bookworm-slim` is a moving tag, and an unpinned base
# silently repoints the userland under artifacts that claim to be reproducible.
# Digest = the linux/amd64 manifest, resolved 2026-08-02 (index sha256:7b140f37…).
#   docker buildx imagetools inspect debian:bookworm-slim
# Non-amd64 hosts must resolve their own platform manifest. The pin is deliberately
# platform-specific: same Dockerfile on a different arch is a different userland and
# should not masquerade as the same environment.
FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e

ENV DEBIAN_FRONTEND=noninteractive

# Archive timestamp. Bump deliberately (see ../CONTRACT.md §"Updating the base"), never
# incidentally — moving it changes the userland that every T0 baseline refers to.
ARG SNAPSHOT=20260513T000000Z

# Point apt at the frozen archive. check-valid-until=no is required: snapshot Release
# files are older than apt's freshness window by construction.
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/*; \
    { echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT} bookworm-security main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm-updates main"; \
    } > /etc/apt/sources.list

# Versions pinned to what that original image contained (dpkg-query, 2026-08-02).
# Belt and braces: SNAPSHOT already determines these, but naming them makes a silent
# substitution impossible — if the snapshot ever serves something else, the build FAILS
# LOUDLY instead of handing you a different userland that still calls itself the same tag.
#
# NOTE bash=5.2.15-2+b13 while the original image carried +b10: that binNMU predates the
# snapshot and is no longer in the archive at any timestamp we can reach. Recorded
# honestly rather than papered over — a rebuild is therefore *equivalent*, not identical,
# and this is precisely the situation ENV-MISMATCH exists to report.
RUN set -eux; \
    apt-get update -o Acquire::Check-Valid-Until=false; \
    apt-get install -y --no-install-recommends \
      bash=5.2.15-2+b13 \
      ca-certificates=20230311+deb12u1 \
      curl=7.88.1-10+deb12u14 \
      git=1:2.39.5-0+deb12u3 \
      jq=1.6-2.1+deb12u1 \
      python3=3.11.2-1+b1 \
      ripgrep=13.0.0-4+b2 \
    ; rm -rf /var/lib/apt/lists/*

# Non-root by contract. The runner adds --read-only and bind-mounts scratch at /work, so
# root would buy nothing and cost containment. UID is deliberately NOT pinned: the bind
# mount is created by the host runner, and pinning a UID that mismatches the host's
# breaks writes to /work for no reproducibility gain.
RUN useradd --create-home --shell /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

# Never executed by the commons runner — it always passes an explicit interpreter and
# script. Present so the image is also usable as a long-lived dev container.
CMD ["sleep", "infinity"]
