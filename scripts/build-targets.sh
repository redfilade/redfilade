#!/usr/bin/env bash
# Build every Range target twin as a static binary inside a FROM-scratch image.
#
# No base image is pulled, so there is nothing to pin or trust beyond our own
# code, and a compromised target has no shell or tools inside its cell.
#   redfilade-target/<name>:vulnerable
#   redfilade-target/<name>:secure
set -euo pipefail
cd "$(dirname "$0")/.."
build_image() { # tag, ldflags-mode, package dir
  local tag="$1" mode="$2" pkg="$3" tmp
  tmp="$(mktemp -d)"
  CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath \
    -ldflags "-s -w -buildid= -X main.mode=${mode}" -o "${tmp}/server" "./${pkg}"
  cat > "${tmp}/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY server /server
USER 65532:65532
ENTRYPOINT ["/server"]
DOCKERFILE
  docker build --quiet --no-cache --label "io.redfilade.image=${tag}" -t "${tag}" "${tmp}" >/dev/null
  rm -rf "${tmp}"
  echo "built ${tag}"
}

# Range infrastructure: the egress sink (never forwards anything).
build_image "redfilade-infra/sink:latest" "" "infra/sink"

for dir in targets/*/; do
  name="$(basename "$dir")"
  [ "$name" = internal ] && continue
  for mode in vulnerable secure; do
    build_image "redfilade-target/${name}:${mode}" "${mode}" "${dir%/}"
  done
done
