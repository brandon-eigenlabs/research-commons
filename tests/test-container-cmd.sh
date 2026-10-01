#!/usr/bin/env bash
# Offline container-runtime selection tests. Uses fake docker/podman executables;
# no container daemon or image is required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
TMP="$(mktemp -d "$REPO/.test-container-cmd.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/container-mock" <<'PY'
#!/usr/bin/env python3
import json, os, pathlib, sys
with open(os.environ["MOCK_CONTAINER_LOG"], "a") as f:
    f.write(json.dumps([pathlib.Path(sys.argv[0]).name] + sys.argv[1:]) + "\n")
if sys.argv[1:3] == ["image", "inspect"]:
    # Tests may supply per-case inspect JSON. The default preserves the original
    # local-image response used by the container-command selection checks.
    print(os.environ.get(
        "MOCK_CONTAINER_INSPECT",
        '[{"Id": "sha256:' + "ab" * 32 + '", "RepoDigests": []}]'))
PY
chmod +x "$TMP/container-mock"
cp "$TMP/container-mock" "$TMP/docker"
cp "$TMP/container-mock" "$TMP/podman"

PATH="$TMP:$PATH" TMPDIR="$TMP" MOCK_CONTAINER_LOG="$TMP/argv.jsonl" \
COMMONS_SOURCE="$REPO/bin/commons" python3 - <<'PY'
import json, os, runpy, tempfile

commons = runpy.run_path(os.environ["COMMONS_SOURCE"])
image_digest = commons["image_digest"]
check_image_allowed = commons["check_image_allowed"]
run_sandboxed = commons["_run_sandboxed"]
log_path = os.environ["MOCK_CONTAINER_LOG"]
passed = 0

def check(name, condition):
    global passed
    if not condition:
        raise AssertionError(name)
    passed += 1
    print("  ok  " + name)

def records():
    try:
        with open(log_path) as f:
            return [json.loads(line) for line in f]
    except FileNotFoundError:
        return []

def clear():
    try:
        os.unlink(log_path)
    except FileNotFoundError:
        pass

def canned(inspected):
    os.environ["MOCK_CONTAINER_INSPECT"] = json.dumps(inspected)

def selected_inspect(runtime, image):
    return records() == [[runtime, "image", "inspect", image]]

def exits(call):
    try:
        call()
    except SystemExit as e:
        return str(e)
    raise AssertionError("expected SystemExit")

image = "research-commons-sandbox:base"
os.environ["COMMONS_CONTAINER_CMD"] = "podman"
check("podman image digest is returned", image_digest(image) == "sha256:" + "ab" * 32)
check("image_digest invokes selected CLI",
      records() == [["podman", "image", "inspect", image]])

clear()
with tempfile.TemporaryDirectory(prefix="commons-container-work-") as scratch:
    spec = {
        "interpreter": "bash",
        "steps": ["echo ok"],
        "env": {"A": "z"},
        "inputs": {"DATA": "ds-abc"},
    }
    policy = {"limits": {"memory": "3g", "cpus": "1.5", "pids": 42,
                         "tmpfs_size": "32m"}}
    result = run_sandboxed(scratch, spec, 17, image, policy)
    expected = [
        "podman", "run", "--rm", "--network=none", "--memory=3g",
        "--cpus=1.5", "--pids-limit=42", "--read-only", "--tmpfs",
        "/tmp:rw,exec,size=32m", "-v", scratch + ":/work:rw", "-w", "/work",
        "-e", "A=z", "-e", "IN_DATA=/work/ds-abc", "-e", "OUT_DIR=/work/out",
        image, "bash", "-c", "set -euo pipefail\necho ok",
    ]
    check("_run_sandboxed accepts mock podman success", result.returncode == 0)
    check("_run_sandboxed preserves isolation and resource argv",
          records() == [expected])

clear()
os.environ.pop("COMMONS_CONTAINER_CMD")
image_digest(image)
check("unset COMMONS_CONTAINER_CMD defaults to docker", records()[0][0] == "docker")

clear()
os.environ["COMMONS_CONTAINER_CMD"] = ""
image_digest(image)
check("empty COMMONS_CONTAINER_CMD preserves docker default", records()[0][0] == "docker")

clear()
os.environ["COMMONS_CONTAINER_CMD"] = "bogus"
try:
    image_digest(image)
except SystemExit as e:
    message = str(e)
else:
    raise AssertionError("bogus COMMONS_CONTAINER_CMD was accepted")
check("bogus value names variable and rejected value",
      "COMMONS_CONTAINER_CMD" in message and "'bogus'" in message)
check("bogus value never invokes a container executable", records() == [])

# Digest-pin seam: drive image_digest and check_image_allowed entirely through the
# same fake docker/podman executables used above.
repo_digest = "sha256:" + "12" * 32
other_digest = "sha256:" + "34" * 32
image_id = "sha256:" + "56" * 32
short_image = "alpine:latest"
qualified_image = "docker.io/library/alpine:latest"
wrong_repo_image = "registry.example/team/tool:stable"

for runtime in ("podman", "docker"):
    os.environ["COMMONS_CONTAINER_CMD"] = runtime

    canned([{
        "Id": image_id,
        "RepoDigests": ["docker.io/library/alpine@" + repo_digest],
    }])
    clear()
    actual = image_digest(short_image)
    check(runtime + " normalized docker.io/library RepoDigest matches and selected CLI runs",
          actual == repo_digest and selected_inspect(runtime, short_image))

    canned([{
        "Id": image_id,
        "RepoDigests": ["index.docker.io/library/alpine@" + repo_digest],
    }])
    clear()
    actual = image_digest(qualified_image)
    check(runtime + " normalized qualified image RepoDigest matches and selected CLI runs",
          actual == repo_digest and selected_inspect(runtime, qualified_image))

    canned([{
        "Id": image_id,
        "RepoDigests": ["registry.example/other/tool@" + repo_digest],
    }])
    clear()
    actual = image_digest(wrong_repo_image)
    check(runtime + " mismatched RepoDigest falls back to image Id and selected CLI runs",
          actual == image_id and selected_inspect(runtime, wrong_repo_image))

    clear()
    message = exits(lambda: image_digest(wrong_repo_image, require_repository=True))
    check(runtime + " mismatched RepoDigest fails closed naming image and selected CLI runs",
          wrong_repo_image in message and "no repository digest" in message
          and selected_inspect(runtime, wrong_repo_image))

    canned([{"RepoDigests": []}])
    clear()
    message = exits(lambda: image_digest(short_image))
    check(runtime + " missing image Id gives clear image-naming error and selected CLI runs",
          short_image in message and "neither a repository digest nor a valid image ID" in message
          and selected_inspect(runtime, short_image))

    canned([{"Id": "sha256:not-a-digest", "RepoDigests": []}])
    clear()
    message = exits(lambda: image_digest(short_image))
    check(runtime + " malformed image Id gives clear image-naming error and selected CLI runs",
          short_image in message and "neither a repository digest nor a valid image ID" in message
          and selected_inspect(runtime, short_image))

    policy = {"images": [short_image + "@" + repo_digest]}
    canned([{
        "Id": image_id,
        "RepoDigests": ["docker.io/library/alpine@" + repo_digest],
    }])
    clear()
    check_image_allowed(short_image, policy)
    check(runtime + " matching digest pin is allowed via selected CLI",
          selected_inspect(runtime, short_image))

    canned([{
        "Id": image_id,
        "RepoDigests": ["docker.io/library/alpine@" + other_digest],
    }])
    clear()
    message = exits(lambda: check_image_allowed(short_image, policy))
    check(runtime + " mismatched digest pin is refused via selected CLI",
          short_image in message and "does not match" in message
          and selected_inspect(runtime, short_image))

    canned([{"Id": "not-a-valid-id", "RepoDigests": []}])
    clear()
    message = exits(lambda: check_image_allowed(short_image, policy))
    check(runtime + " unusable inspect data refuses digest pin closed via selected CLI",
          short_image in message and "refusing closed" in message
          and selected_inspect(runtime, short_image))

print(f"\ntest-container-cmd: {passed} passed, 0 failed")
PY
