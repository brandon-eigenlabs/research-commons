# Execution environment contract

**What this is:** the complete set of guarantees a container image must provide to run
research-commons workflows. Satisfy it and you are a first-class participant — you do
not need the default image, its base distro, or its package manager.

**Why it exists:** requiring everyone to run one blessed image does not scale. One image
cannot hold every dependency research needs, and an image that tries becomes a monolith
with a single maintainer acting as a package-approval committee. The alternative is a
*contract*: many images, each pinned and recorded per workflow, all interoperable because
they agree on this interface.

Reference implementation: [`base/Dockerfile`](base/Dockerfile) — the recipe for
`research-commons-sandbox:base`, the default image in `registry/exec-policy.example.json`
(and in the built-in fallback policy). It is not pulled from anywhere; build it locally
before the first sandboxed run:

```bash
docker build -t research-commons-sandbox:base environments/base/
```

Rungs 0–2 (read, verify in-process, publish, and federate) require no container runtime.
The rung-3 sandbox invokes a container CLI directly: Docker is the default, and this
snapshot also supports Podman when `COMMONS_CONTAINER_CMD=podman` is set.

---

## 1. The contract

An image MUST:

1. **Provide the interpreter the workflow spec names.** `spec.interpreter` defaults to
   `bash`; the runner invokes `<interpreter> -c <script>`. If your workflows use
   `python3`, ship python3. Nothing is auto-installed at run time — there is no network.
2. **Run as a non-root user.** The runner adds `--read-only` and mounts scratch at
   `/work`; root buys nothing and costs containment.
3. **Be able to write to `/work` and `/work/out`.** A host bind mount, created by the
   runner. Do **not** pin a UID that mismatches the host user — writes to `/work` will
   fail for no reproducibility gain. (This is why the reference image does not pin UID.)
4. **Function with no network whatsoever.** The runner passes `--network=none`. Any image
   that fetches dependencies at run time is unusable here, by design: a workflow that
   downloads something is not reproducible.
5. **Tolerate a read-only root filesystem.** Only `/work` (rw bind) and `/tmp`
   (tmpfs, `exec`, default 256m) are writable. Anything writing to `$HOME` or `/usr`
   at run time will fail.
6. **Not depend on host environment variables.** Only these cross the boundary:
   - every key in the spec's own `env` block;
   - `OUT_DIR=/work/out` — where outputs must be written;
   - `IN_<NAME>=/work/<basename>` — one per entry in the spec's `inputs`.

   The host environment is withheld deliberately. If your workflow needs a value, it
   must be declared in the spec, where it is recorded in provenance.

   **This applies to `--exec native` too, as of 2026-08-12.** A native run receives only
   `PATH` and `HOME` (the minimum needed to locate an interpreter on an unpinned host)
   plus the spec's declared `env`. Native mode previously inherited the whole host
   environment while recording only `spec.env`, which made an undeclared host variable an
   undeclared *input*: it could change the output bytes while leaving provenance
   byte-identical, so the publisher verified PASS and everyone else FAILed. Sandbox mode
   was never affected. The regression is pinned in `tests/test-tiers.sh` ("native exec:
   undeclared host env is not an input").

   Native mode remains weaker than sandbox regardless: `PATH`/`HOME` values, the
   interpreter build, and the userland are the host's and are not fully recorded. A claim
   that needs a pinned userland must declare `image` and run sandboxed — the runner
   already refuses to run an image-declaring spec natively rather than silently
   substituting a different environment.
7. **Work under the policy's resource caps.** Defaults from
   `registry/exec-policy.json`: memory 2g, cpus 2, pids 256, tmpfs 256m, output 1 GiB.
   The timeout is enforced *outside* the container.

An image SHOULD:

8. **Be reproducibly built** — pinned base digest, pinned package versions, and a pinned
   *archive* (see §3; pinning versions alone is not enough).
9. **Set deterministic locale/time/hash defaults where the workflow doesn't.** The
   reference workflows set `TZ=UTC`, `LC_ALL=C`, `PYTHONHASHSEED=0` in the spec's `env`
   block, which is the better place for them: recorded in provenance, and applies
   whichever image runs. Treat this as doctrine for anything touching sort order,
   formatting, or hashing.

---

## 2. Registering your image

The allowlist in `registry/exec-policy.json` is the gate: a workflow may only request an
image listed there, and an unknown image is refused rather than pulled.

```jsonc
{
  "default_image": "research-commons-sandbox:base",
  "images": [
    "research-commons-sandbox:base",
    "my-org/geospatial:2026-08"      // ← your image
  ],
  "limits": { "memory": "2g", "cpus": "2", "pids": 256 }
}
```

⚠️ **`registry/exec-policy.json` is local-only and never replicates.** It is *your*
policy: it decides what may execute on *your* machine and under what caps. A peer cannot
hand you one — an incoming tree carrying it is refused outright, the same rule that
protects `peers.json`. Consequences:

- Adding an image to your allowlist does **not** add it to anyone else's. A peer
  verifying your artifact must make that decision themselves. That is the point.
- On a fresh clone the file is absent and is seeded from the tracked
  `registry/exec-policy.example.json` on first use. Edit your local copy, not the example.

Tags are resolved to a **digest** at run time and the digest is recorded in
`provenance.run.exec.image_digest`. Tags drift; the recorded digest is what a T0 claim
actually refers to.

---

## 3. Pinning that survives contact with reality

Pinning package versions is necessary and **not sufficient**. The first draft of
`base/Dockerfile` pinned exact versions against the normal Debian mirrors and failed to
build *the same day it was written*:

```
E: Version '5.2.15-2+b10' for 'bash' was not found
E: Version '7.88.1-10+deb12u14' for 'curl' was not found
```

The pins were correct. The mirrors had rolled 12.13 → 12.15 and garbage-collected the
old versions. Pins are only as durable as the archive behind them, so pin the archive
too — `snapshot.debian.org` serves the archive as of a timestamp, making the package set
a function of the snapshot rather than of your build date. Equivalents exist elsewhere
(Nix flake inputs, `conda-lock`, Alpine's tagged repos, RHEL vault); the principle is the
same regardless of distro.

**Honest accounting for the reference image:** the recipe was first written to reproduce
an image built earlier from the live mirrors. At snapshot `20260513T000000Z`, 6 of 7
packages match that original byte-for-byte. `bash` resolves to `5.2.15-2+b13` against
the original's `+b10` — a binNMU no longer in any reachable archive. A rebuild is
therefore *equivalent*, not *identical*, and the docs say so rather than implying a
guarantee that does not hold. Two builds of this recipe get the same package set but,
in general, different image digests.

---

## 4. When digests differ

**A different digest is expected and is not a failure.** Rebuilding cannot generally
reproduce someone else's image digest — timestamps, build order, and archive state all
leak in.

`commons verify` distinguishes the two cases and this is the single most important
behaviour in the system:

| Outcome | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | reproduced. If the environment also differed: *stronger* evidence — the note reads `result is environment-independent` |
| `ENV-MISMATCH` | **5** | did not reproduce, **but was run in a different userland**. The question was asked in the wrong place; this is information, not a wrong answer |
| `FAIL` | 1 | did not reproduce **in the recorded environment**. A real finding |

`ENV-MISMATCH` never lowers a chain grade and never counts as a verification failure.
`commons rebaseline <id>` converges an artifact onto your environment: **MATCH** (stamp
it), **DIVERGED** (`--publish-superseding`), **NONDETERMINISTIC** (a genuine defect in
the workflow).

**Verified end-to-end**, against the synthetic demo hub (`scripts/demo-hub.sh` — see
README.md's "Demo hub artifacts"). The hub's T0 synthesis was produced under the default
image; a second, independent `--no-cache` build of the same `base/Dockerfile` got a
different digest (`sha256:355660016ea8` vs `sha256:a2625e3e5113`) and reproduced
`sy-c775b533` byte-identically:

```
PASS: sy-c775b533 reproduced byte-identically from wf-1e4e0c5e
  environment: sandbox research-commons-demo-base:probe @sha256:355660016ea8
  note: recorded environment was sandbox research-commons-sandbox:base
        @sha256:a2625e3e5113 — result is environment-independent
```

(An earlier run of this drill, against an image built from the live mirrors rather than
the snapshot, also passed despite the `bash` `+b13`/`+b10` difference described in §3.)

That is the whole argument for this contract: an *independently rebuilt* image, not
pulled from the publisher, verifying the publisher's artifact. Your digests will differ
from the ones above; the PASS should not. Reproduce it yourself:

```bash
docker build -t research-commons-sandbox:base environments/base/  # the default image
scripts/demo-hub.sh /tmp/my-demo-hub                          # note the printed ROOT
docker build --no-cache -t research-commons-demo-base:probe environments/base/
# add "research-commons-demo-base:probe" to <ROOT>/registry/exec-policy.json's
# "images" list and set it as "default_image", then:
COMMONS_ROOT=/tmp/my-demo-hub/hub commons verify sy-c775b533 --exec sandbox
```

### Choosing the right tier

If your result should not depend on the userland, **do not claim T0** — declare **T1
with a comparator** and it won't:

```bash
commons publish synthesis out.json "Floats" --tier T1 \
  --criteria sk-<json-numeric-epsilon> --param EPSILON=1e-6
```

T1 is not a downgrade. For anything touching floating point, hash/sort order, locale, or
a library's formatting, T1 is the *correct* tier and T0 is an over-claim. Over-claiming
T0 produces `ENV-MISMATCH` everywhere and trains people to ignore it — the failure mode
worth avoiding most.

---

## 5. Updating the base

Moving `SNAPSHOT` or the base digest changes the userland every T0 baseline refers to.
Do it deliberately:

1. Bump `ARG SNAPSHOT` and/or the `FROM` digest; refresh version pins to match.
2. Rebuild and re-run `tests/run-all.sh sandbox`.
3. Re-verify existing T0 artifacts. Expect `ENV-MISMATCH` (5), not `FAIL` (1).
4. `commons rebaseline <id>` each affected artifact; publish superseding artifacts where
   output genuinely changed.
5. Record the change — a userland move that nobody announced looks exactly like a
   reproducibility failure to everyone else.

---

## 6. Runtimes other than Docker

The runner shells out to `docker` by default. `COMMONS_CONTAINER_CMD=podman` selects
podman instead (`container_cmd()`; pinned by `tests/test-container-cmd.sh`); any other
value is refused. Every flag used — `--network=none`, `--read-only`, `--memory`, `--cpus`,
`--pids-limit`, `--tmpfs`, `-v`, `-w`, `-e` — is podman-compatible, and rootless podman
removes the last step that needs `sudo` (no daemon, no group membership).

Rungs 0-1 — reading, and verifying T0/T1 natively — need **no container runtime at all**.


## Local allowlisting and digest pins

`registry/exec-policy.json` is local trust policy. Workflow image tags are allowed by
entries in its `images` array. Two forms are accepted:

```json
{
  "default_image": "registry.example/research:2026-08",
  "images": [
    "registry.example/research:2026-08@sha256:ELIDED64HEX"
  ]
}
```

- A legacy plain-tag entry such as `registry.example/research:2026-08` retains the
  historical exact-string behavior.
- A `tag@sha256:<64-hex>` entry allows that tag only when Docker reports the same
  repository digest for the locally available candidate image.
- A malformed pin is a policy error. The tag must be non-empty and the digest must be
  exactly 64 hexadecimal characters.
- If the daemon cannot be reached, the image is not present, or it has no repository
  digest (common for a locally built image that was never pushed/pulled), a
  digest-pinned entry fails closed. A local image ID is not accepted as proof of a
  repository digest.

Use digest pins for blessed or shared images. Plain tags remain supported for
backward compatibility, but tags can be repushed to different bytes without changing
the policy string. Keep `default_image` and workflow `image` values as the candidate
tag; place the `tag@sha256:...` form in the allowlist.

The resolved digest is recorded in `provenance.run.exec.image_digest`; environment
differences continue to surface as `ENV-MISMATCH`, not as a false verification
failure.

## Container runtime selection

`COMMONS_CONTAINER_CMD` selects the CLI:

- unset or empty: `docker` (the historical default);
- `docker`: Docker CLI, including Docker Desktop installations;
- `podman`: Podman CLI, including installations supplied by Podman Desktop.

Other nonempty values fail with an error naming `COMMONS_CONTAINER_CMD` and the
rejected value. The value is a CLI selector, not a shell command, so arguments or
wrappers are not accepted.

Rootless Podman is the sudo-free rung-3 path. It does not require a daemon or
membership in a privileged daemon group:

```bash
COMMONS_CONTAINER_CMD=podman commons run wf-abc --exec sandbox
```

The Docker- and Podman-selected paths use the same image inspection, allowlist
decision, resource limits, mount, read-only-root, and no-network arguments.

### Digest resolution trust boundary

Digest resolution and digest-pin allowlist checks run through the runtime selected by
COMMONS_CONTAINER_CMD; selecting Podman does not silently consult Docker, or vice
versa. A pin is therefore only as strong as that runtime's truthful RepoDigests
inspection result. A peer's daemon is not your daemon: each peer resolves and trusts
the image metadata reported by its own selected runtime.
