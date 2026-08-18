#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <exact-platform-source-directory>" >&2
  exit 64
}

[[ $# -eq 1 ]] || usage

capa_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
platform_source="$(cd "$1" && pwd -P)"
model_source="${platform_source}/model"

[[ -f "${capa_root}/go.mod" && \
  -f "${platform_source}/go.mod" && \
  -d "${platform_source}/pkg/capacityfence" && \
  -f "${model_source}/go.mod" ]] || {
  echo "exact Platform source lacks the owner-bound capacity-fence layout" >&2
  exit 65
}

for source in "${capa_root}" "${platform_source}"; do
  git -C "${source}" rev-parse --verify HEAD^{commit} >/dev/null
  [[ -z "$(git -C "${source}" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "owner-bound source is not clean: ${source}" >&2
    exit 65
  }
done

workspace="$(mktemp -d)"
trap 'rm -rf "${workspace}"' EXIT
(
  cd "${workspace}"
  go work init "${capa_root}" "${platform_source}" "${model_source}"
)
go_work="${workspace}/go.work"

(
  cd "${platform_source}"
  GOWORK="${go_work}" go test ./pkg/capacityfence
)
(
  cd "${capa_root}"
  GOWORK="${go_work}" go test -vet=off ./pkg/capacityfenceadapter ./pkg/cloud/services/ec2
  GOWORK="${go_work}" go build -o "${workspace}/manager" .
  go tool nm "${workspace}/manager" |
    grep -Fq 'sigs.k8s.io/cluster-api-provider-aws/v2/pkg/capacityfenceadapter'
)
