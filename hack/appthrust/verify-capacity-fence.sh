#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <exact-platform-source-directory>" >&2
  exit 64
}

[[ $# -eq 1 ]] || usage

capa_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
platform_source="$1"

workspace="$(mktemp -d)"
trap 'rm -rf "${workspace}"' EXIT
go_work="${workspace}/go.work"
"${capa_root}/hack/appthrust/prepare-capacity-fence-workspace.sh" \
  "${platform_source}" \
  "${go_work}"

(
  cd "${platform_source}"
  GOWORK="${go_work}" go test ./pkg/capacityfence
)
(
  cd "${capa_root}"
  GOWORK="${go_work}" go test -tags=appthrust_owner_bound -vet=off ./pkg/capacityfenceadapter ./pkg/capacityfenceintegration ./pkg/cloud/services/ec2
  GOWORK="${go_work}" go vet -tags=appthrust_owner_bound ./pkg/capacityfenceadapter ./pkg/capacityfenceintegration
  GOWORK="${go_work}" go build -tags=appthrust_owner_bound -o "${workspace}/manager" .
  go tool nm "${workspace}/manager" |
    awk 'index($0, "sigs.k8s.io/cluster-api-provider-aws/v2/pkg/capacityfenceadapter") { found = 1 } END { exit found ? 0 : 1 }'
)
