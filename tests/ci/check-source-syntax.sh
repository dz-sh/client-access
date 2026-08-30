#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}

find "${repo_dir}/root/usr/share/luci/menu.d" \
  "${repo_dir}/root/usr/share/rpcd/acl.d" \
  "${repo_dir}/tests/architecture" \
  -name '*.json' -print0 | xargs -0 -n1 jq empty

find "${repo_dir}/root/etc" -type f \
  \( -path '*/init.d/*' -o -path '*/hotplug.d/*' \) \
  -print0 | xargs -0 -n1 sh -n

find "${repo_dir}/tests" -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
find "${repo_dir}/tests" -type f -name '*.py' -print0 | xargs -0 -n1 python3 -m py_compile
