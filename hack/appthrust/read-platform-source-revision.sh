#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 0 ]] || {
  echo "usage: $0" >&2
  exit 64
}

capa_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
pin_relative="hack/appthrust/platform-source-revision"
pin_file="${capa_root}/${pin_relative}"

[[ -f "${pin_file}" && ! -L "${pin_file}" ]] || {
  echo "Platform source pin is absent or indirect" >&2
  exit 65
}
git -C "${capa_root}" ls-files --error-unmatch -- "${pin_relative}" >/dev/null
mapfile -t revisions <"${pin_file}"
[[ ${#revisions[@]} -eq 1 && "${revisions[0]}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "Platform source pin must contain exactly one lowercase 40-hex revision" >&2
  exit 65
}
printf '%s\n' "${revisions[0]}"
