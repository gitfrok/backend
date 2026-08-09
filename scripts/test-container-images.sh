#!/usr/bin/env bash
# T-0021 AC1/AC3: build both plane images and assert the ADR-0035 runtime posture.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail=0
report() { echo "container-images: FAIL — $*" >&2; fail=1; }

runtime=${CONTAINER_RUNTIME:-}
if [ -z "$runtime" ]; then
  if command -v docker >/dev/null; then
    runtime=docker
  elif command -v podman >/dev/null; then
    runtime=podman
  else
    echo "container-images: neither docker nor podman is available" >&2
    exit 2
  fi
fi

for plane in dataplane controlplane; do
  file="$root/Dockerfile.$plane"
  [ -f "$file" ] || { report "missing Dockerfile.$plane"; continue; }

  image="localhost/gitfrok-$plane:test"
  "$runtime" build --file "$file" --tag "$image" "$root"

  user=$("$runtime" image inspect "$image" --format '{{.Config.User}}')
  [ "$user" = "65532:65532" ] || report "$plane image user is '$user', want 65532:65532"

  cmd=$("$runtime" image inspect "$image" --format '{{json .Config.Cmd}}')
  [ "$cmd" = "[\"/$plane-app\"]" ] || report "$plane image command is '$cmd'"

  # `scratch` contains no shell. Trying one is an image-level assertion rather than an inference
  # from the Dockerfile; a future base-image change cannot silently weaken this posture.
  if "$runtime" run --rm "$image" /bin/sh >/dev/null 2>&1; then
    report "$plane image unexpectedly contains /bin/sh"
  fi
done

# A read-only root filesystem is a runtime setting, not an OCI-image field. The control plane has
# no required writable mount, so it is the smallest built-image proof that the binaries tolerate it.
"$runtime" run --rm --read-only localhost/gitfrok-controlplane:test >/dev/null

[ "$fail" -eq 0 ] || exit 1
echo "container-images: OK"
