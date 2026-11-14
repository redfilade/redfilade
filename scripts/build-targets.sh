#!/usr/bin/env bash
# Build every Range target twin as a static binary inside a FROM-scratch image.
#
# No base image is pulled, so there is nothing to pin or trust beyond our own
# code, and a compromised target has no shell or tools inside its cell.
#   redfilade-target/<name>:vulnerable
#   redfilade-target/<name>:secure
set -euo pipefail
cd "$(dirname "$0")/.."
for dir in targets/*/; do
  name="$(basename "$dir")"
  for mode in vulnerable secure; do
    tmp="$(mktemp -d)"
    CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath \
      -ldflags "-s -w -buildid= -X main.mode=${mode}" -o "${tmp}/server" "./${dir}"
    cat > "${tmp}/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY server /server
USER 65532:65532
ENTRYPOINT ["/server"]
DOCKERFILE
    docker build --quiet --no-cache \
      --label "io.redfilade.target=${name}" --label "io.redfilade.build=${mode}" \
      -t "redfilade-target/${name}:${mode}" "${tmp}" >/dev/null
    rm -rf "${tmp}"
    echo "built redfilade-target/${name}:${mode}"
  done
done
