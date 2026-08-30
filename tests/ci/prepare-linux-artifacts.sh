#!/bin/bash
set -euo pipefail

artifact_dir=${1:?artifact directory is required}
work_dir=${2:?working directory is required}

(
  cd "${artifact_dir}"
  sha256sum --check SHA256SUMS
)

# GitHub artifact transport does not preserve executable mode bits.
chmod 0755 \
  "${artifact_dir}/client-access-bpfctl" \
  "${artifact_dir}/client-access-sfoctl"

for artifact in client-access-bpf.o foreign-tc-bpf.o \
  client-access-bpfctl client-access-sfoctl; do
  ln -sf "${artifact_dir}/${artifact}" "${work_dir}/${artifact}"
done
