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

# ADR-0048: git-storaged is the one first-party Go image with a base, because its
# whole job is to execute git. The assertions are therefore the opposite of the
# planes' — it MUST contain git and a shell — plus the parts of the ADR-0035
# posture that still apply.
gitstoraged_file="$root/Dockerfile.gitstoraged"
if [ ! -f "$gitstoraged_file" ]; then
  report "missing Dockerfile.gitstoraged"
else
  gitstoraged_image="localhost/gitfrok-git-storaged:test"
  "$runtime" build --file "$gitstoraged_file" --tag "$gitstoraged_image" "$root"

  user=$("$runtime" image inspect "$gitstoraged_image" --format '{{.Config.User}}')
  [ "$user" = "65532:65532" ] || report "git-storaged image user is '$user', want 65532:65532"

  entrypoint=$("$runtime" image inspect "$gitstoraged_image" --format '{{json .Config.Entrypoint}}')
  [ "$entrypoint" = '["/git-storaged"]' ] || report "git-storaged entrypoint is '$entrypoint'"

  # The failure this image exists to avoid: a correct binary in an image that
  # cannot run the programs it shells out to. The Dockerfile asserts this at build
  # time; asserting it again on the built image means a base change cannot quietly
  # remove git and still ship.
  for program in git git-upload-pack git-receive-pack; do
    if ! "$runtime" run --rm --entrypoint /bin/sh "$gitstoraged_image" -c "command -v $program" >/dev/null 2>&1; then
      report "git-storaged image has no $program — every Git operation would fail at runtime"
    fi
  done
fi

# A read-only root filesystem is a runtime setting, not an OCI-image field. The data plane proves
# its deliberate no-policy fail-fast here. The real policy-bundle mount needs governance, which is
# intentionally not a backend CI dependency; the super-repo dev-cluster integration owns that
# assertion. The control plane has no such mount and therefore proves a built image stays healthy.
if "$runtime" run --rm --read-only localhost/gitfrok-dataplane:test >/dev/null 2>&1; then
  report "dataplane started without GITFROK_POLICY_BUNDLE_DIR"
fi

run_health() { # run_health <plane>
  plane=$1
  image="localhost/gitfrok-$plane:test"
  name="gitfrok-${plane}-health-$$"
  args=(run --detach --rm --read-only --name "$name" -p 127.0.0.1::8080)
  if ! container=$("$runtime" "${args[@]}" "$image"); then
    report "$plane did not start with a read-only root filesystem"
    return
  fi
  port=$("$runtime" port "$container" 8080/tcp 2>/dev/null | head -1 || true)
  case "$port" in
    127.0.0.1:*) ;; *)
      report "$plane did not publish a loopback health port"
      "$runtime" stop "$container" >/dev/null 2>&1 || true
      return
      ;;
  esac

  body=
  for _ in {1..50}; do
    body=$(curl --silent --show-error --fail "http://$port/healthz" 2>/dev/null || true)
    [ "$body" = ok ] && break
    sleep 0.1
  done
  if [ "$body" != ok ]; then
    report "$plane health endpoint did not answer ok"
  fi
  "$runtime" stop "$container" >/dev/null 2>&1 || report "$plane did not stop cleanly"
}

run_health controlplane

[ "$fail" -eq 0 ] || exit 1
echo "container-images: OK"
