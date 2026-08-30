#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}
feed_dir=${2:?feed directory is required}

package_dir=${feed_dir}/luci-app-client-access
mkdir -p "${package_dir}"
rsync -a --delete --exclude '.git' --exclude '.github' \
  "${repo_dir}/" "${package_dir}/"
