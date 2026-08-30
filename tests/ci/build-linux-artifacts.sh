#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}
output_dir=${2:?output directory is required}

mkdir -p "${output_dir}"

clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c "${repo_dir}/src/client-access-bpf.c" \
  -o "${output_dir}/client-access-bpf.o"

clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c "${repo_dir}/tests/foreign-tc-bpf.c" \
  -o "${output_dir}/foreign-tc-bpf.o"

cc -O2 -Wall -Wextra -Werror -std=gnu11 \
  "${repo_dir}/src/client-access-bpfctl.c" \
  "${repo_dir}/src/bpfctl-common.c" \
  "${repo_dir}"/src/bpf-*.c \
  -o "${output_dir}/client-access-bpfctl" \
  -lbpf -lelf -lz

cc -O2 -Wall -Wextra -Werror -std=gnu11 \
  -I"${repo_dir}/src" \
  "${repo_dir}/sfo/client-access-sfoctl.c" \
  -o "${output_dir}/client-access-sfoctl" \
  -lbpf -lnetfilter_conntrack

python3 "${repo_dir}/tests/ci/check-undefined-symbols.py" \
  "${output_dir}/client-access-sfoctl" system popen

{
  printf 'source_commit=%s\n' "${GITHUB_SHA}"
  printf 'runner_os=%s\n' "${RUNNER_OS}"
  printf 'compiler=%s\n' "$(cc --version | sed -n '1p')"
  printf 'clang=%s\n' "$(clang --version | sed -n '1p')"
  printf 'build_flags=%s\n' '-O2 -Wall -Wextra -Werror'
} >"${output_dir}/build-manifest.txt"

(
  cd "${output_dir}"
  sha256sum client-access-bpf.o foreign-tc-bpf.o \
    client-access-bpfctl client-access-sfoctl build-manifest.txt \
    >SHA256SUMS
)
