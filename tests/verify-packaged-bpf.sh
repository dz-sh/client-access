#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

artifacts_dir=$1
work_dir=$2
package=$(find "$artifacts_dir" -type f -name 'client-access-bpf_*.ipk' -print -quit)

if [ -z "$package" ]; then
	echo "client-access-bpf package was not produced" >&2
	exit 1
fi

rm -rf "$work_dir"
mkdir -p "$work_dir/package"
(
	cd "$work_dir/package"
	ar x "$package"
	data_archive=$(find . -maxdepth 1 -type f -name 'data.tar.*' -print -quit)
	if [ -z "$data_archive" ]; then
		echo "package has no data archive" >&2
		exit 1
	fi
	tar -xf "$data_archive"
)

object="$work_dir/package/usr/lib/bpf/client-access-bpf.o"
if [ ! -s "$object" ]; then
	echo "package has no non-empty client-access-bpf.o" >&2
	exit 1
fi

cc -O2 -Wall -Wextra -Werror -std=gnu11 \
	src/client-access-bpfctl.c \
	-o "$work_dir/client-access-bpfctl" \
	-lbpf -lelf -lz

cleanup() {
	sudo "$work_dir/client-access-bpfctl" unload >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo mkdir -p /sys/fs/bpf
if ! mountpoint --quiet /sys/fs/bpf; then
	sudo mount -t bpf bpf /sys/fs/bpf
fi
sudo "$work_dir/client-access-bpfctl" load "$object"
sudo "$work_dir/client-access-bpfctl" status >"$work_dir/status.json"
jq -e '
	.backend_mode == "V4_BPF_BASIC" and
	.bpf_schema_version == 2 and
	.program_pinned == true and
	.maps_pinned == true
' "$work_dir/status.json"
sudo "$work_dir/client-access-bpfctl" unload
trap - EXIT
