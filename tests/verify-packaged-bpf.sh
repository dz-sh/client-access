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
	if tar -tf "$package" >/dev/null 2>&1; then
		echo "IPK container: tar"
		tar -xf "$package"
	elif ar t "$package" >/dev/null 2>&1; then
		echo "IPK container: ar"
		ar x "$package"
	else
		echo "unsupported IPK container format: $package" >&2
		exit 1
	fi
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
	src/client-access-bpfctl.c src/bpfctl-common.c src/bpf-*.c \
	-o "$work_dir/client-access-bpfctl" \
	-lbpf -lelf -lz

cleanup() {
	sudo ip netns del ca-pkg-ns >/dev/null 2>&1 || true
	sudo ip link del ca-pkg-a >/dev/null 2>&1 || true
	sudo "$work_dir/client-access-bpfctl" unload >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo mkdir -p /sys/fs/bpf
if ! mountpoint --quiet /sys/fs/bpf; then
	sudo mount -t bpf bpf /sys/fs/bpf
fi
sudo "$work_dir/client-access-bpfctl" load "$object"
sudo ip netns add ca-pkg-ns
sudo ip link add ca-pkg-a type veth peer name ca-pkg-b
sudo ip link set ca-pkg-b netns ca-pkg-ns
sudo ip netns exec ca-pkg-ns ip link set lo up
sudo ip netns exec ca-pkg-ns ip link set ca-pkg-b \
	address 02:00:00:00:00:42
sudo ip address add 192.0.2.1/24 dev ca-pkg-a
sudo ip netns exec ca-pkg-ns ip address add 192.0.2.2/24 dev ca-pkg-b
sudo ip link set ca-pkg-a up
sudo ip netns exec ca-pkg-ns ip link set ca-pkg-b up
sudo "$work_dir/client-access-bpfctl" attach ca-pkg-a
printf '%s\n' \
	'CONFIG 1 1 1 0 0 1 256 200 256 512 64' \
	'SUBJECT 02:00:00:00:00:42 42' \
	'POLICY 42 1 0' \
	'POLICY 42 0 0' \
	| sudo "$work_dir/client-access-bpfctl" sync
sudo "$work_dir/client-access-bpfctl" health 1 1 ca-pkg-a
sudo ip netns exec ca-pkg-ns ping -c 1 -W 1 192.0.2.1
sudo "$work_dir/client-access-bpfctl" status >"$work_dir/status.json"
jq -e '
	.backend_mode == "V4_BPF_BASIC" and
	.bpf_schema_version == 4 and
	.program_pinned == true and
	.maps_pinned == true and
	.flow_map_entries >= 1 and
	.flows_total >= 1 and
	.packet_app_allow_verdicts >= 1
' "$work_dir/status.json"
sudo "$work_dir/client-access-bpfctl" detach ca-pkg-a
sudo ip netns del ca-pkg-ns
sudo "$work_dir/client-access-bpfctl" unload
trap - EXIT
