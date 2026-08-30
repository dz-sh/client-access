#!/bin/bash
set -euo pipefail

tool_dir=${1:?tool directory is required}
bpftool_path=$(find /usr/lib/linux-tools -path '*-generic/bpftool' -print -quit)

test -x "${bpftool_path}"
mkdir -p "${tool_dir}"
ln -sf "${bpftool_path}" "${tool_dir}/bpftool"
sudo ln -sf "${bpftool_path}" /usr/local/bin/bpftool
echo "${tool_dir}" >>"${GITHUB_PATH}"
