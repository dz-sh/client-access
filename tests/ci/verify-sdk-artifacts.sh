#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}
artifact_dir=${2:?artifact directory is required}
evidence_dir=${3:?evidence directory is required}

bash "${repo_dir}/tests/verify-packaged-bpf.sh" \
  "${artifact_dir}" \
  "${evidence_dir}/packaged-bpf"

bash "${repo_dir}/tests/verify-v46-packages.sh" \
  "${artifact_dir}" \
  "${evidence_dir}/v46-package-evidence"
