#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <exact-platform-source-directory> <output-go-work>" >&2
  exit 64
}

[[ $# -eq 2 ]] || usage

capa_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
platform_source="$(cd "$1" && pwd -P)"
model_source="${platform_source}/model"
go_work="$2"

[[ "$(basename "${go_work}")" == "go.work" ]] || {
  echo "output workspace must be named go.work" >&2
  exit 64
}
[[ ! -e "${go_work}" && ! -L "${go_work}" ]] || {
  echo "output workspace already exists" >&2
  exit 65
}
platform_revision="$("${capa_root}/hack/appthrust/read-platform-source-revision.sh")"

for file in \
  "${capa_root}/go.mod" \
  "${platform_source}/go.mod" \
  "${model_source}/go.mod"; do
  [[ -f "${file}" && ! -L "${file}" ]] || {
    echo "exact source module file is absent or indirect: ${file}" >&2
    exit 65
  }
done
[[ -d "${platform_source}/pkg/capacityfence" && ! -L "${platform_source}/pkg/capacityfence" ]] || {
  echo "exact Platform source lacks pkg/capacityfence" >&2
  exit 65
}

for source in "${capa_root}" "${platform_source}"; do
  git -C "${source}" rev-parse --verify 'HEAD^{commit}' >/dev/null
  [[ -z "$(git -C "${source}" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "owner-bound source is not clean: ${source}" >&2
    exit 65
  }
done
[[ "$(git -C "${platform_source}" rev-parse HEAD)" == "${platform_revision}" ]] || {
  echo "Platform checkout does not match the tracked source pin" >&2
  exit 65
}

mkdir -p "$(dirname "${go_work}")"
(
  cd "$(dirname "${go_work}")"
  go work init "${capa_root}" "${platform_source}" "${model_source}"
)
[[ -f "${go_work}" && ! -L "${go_work}" ]] || {
  echo "exact Go workspace was not created" >&2
  exit 65
}
