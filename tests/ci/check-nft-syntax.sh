#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}
output=${2:?output path is required}

{
  echo 'table inet fw4 {'
  sed -n '1,$p' "${repo_dir}/root/usr/share/nftables.d/table-pre/30-client-access.nft"
  echo 'chain forward {'
  echo 'type filter hook forward priority filter; policy accept;'
  sed -n '1,$p' "${repo_dir}/root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft"
  echo '}'
  echo '}'
} >"${output}"

nft --check --file "${output}"
