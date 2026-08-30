#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

object=$1
controller=$2
report_dir=$3

cleanup() {
	if [ -n "${iperf_pid:-}" ]; then
		sudo kill "$iperf_pid" >/dev/null 2>&1 || true
	fi
	if [ -e /var/run/netns/ca-perf-router ]; then
		sudo nsenter --net=/var/run/netns/ca-perf-router -- \
			"$controller" detach ca-perf-br >/dev/null 2>&1 || true
	fi
	sudo ip netns del ca-perf-client >/dev/null 2>&1 || true
	sudo ip netns del ca-perf-server >/dev/null 2>&1 || true
	sudo ip netns del ca-perf-router >/dev/null 2>&1 || true
	sudo "$controller" unload >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$report_dir"
sudo mkdir -p /sys/fs/bpf
if ! mountpoint --quiet /sys/fs/bpf; then
	sudo mount -t bpf bpf /sys/fs/bpf
fi
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo "$controller" load "$object"
sudo bpftool -j map show pinned /sys/fs/bpf/client_access/ca_flows \
	>"$report_dir/flow-map-empty.json"

sudo ip netns add ca-perf-router
sudo ip netns add ca-perf-client
sudo ip netns add ca-perf-server
sudo ip link add ca-perf-lan type veth peer name ca-pc
sudo ip link add ca-perf-wan type veth peer name ca-perf-server
sudo ip link set ca-perf-lan netns ca-perf-router
sudo ip link set ca-perf-wan netns ca-perf-router
sudo ip link set ca-pc netns ca-perf-client
sudo ip link set ca-perf-server netns ca-perf-server

sudo ip netns exec ca-perf-router ip link set lo up
sudo ip netns exec ca-perf-router ip link add ca-perf-br type bridge
sudo ip netns exec ca-perf-router ip link add link ca-perf-lan \
	name ca-perf-lan.42 type vlan id 42
sudo ip netns exec ca-perf-router ip link set ca-perf-lan up
sudo ip netns exec ca-perf-router ip link set ca-perf-lan.42 master ca-perf-br
sudo ip netns exec ca-perf-router ip link set ca-perf-lan.42 up
sudo ip netns exec ca-perf-router ip link set ca-perf-br up
sudo ip netns exec ca-perf-router ip link set ca-perf-wan up
sudo ip netns exec ca-perf-router ip address add 192.0.2.1/24 dev ca-perf-br
sudo ip netns exec ca-perf-router ip address add 198.51.100.1/24 dev ca-perf-wan

sudo ip netns exec ca-perf-client ip link set lo up
sudo ip netns exec ca-perf-client ip link set ca-pc \
	address 02:00:00:00:00:42
sudo ip netns exec ca-perf-client ip link set ca-pc up
sudo ip netns exec ca-perf-client ip link add link ca-pc \
	name ca-pc.42 type vlan id 42
sudo ip netns exec ca-perf-client ip link set ca-pc.42 up
sudo ip netns exec ca-perf-client ip address add \
	192.0.2.2/24 dev ca-pc.42
sudo ip netns exec ca-perf-client ip route add default via 192.0.2.1

sudo ip netns exec ca-perf-server ip link set lo up
sudo ip netns exec ca-perf-server ip link set ca-perf-server up
sudo ip netns exec ca-perf-server ip address add \
	198.51.100.2/24 dev ca-perf-server
sudo ip netns exec ca-perf-server ip route add \
	192.0.2.0/24 via 198.51.100.1
sudo ip netns exec ca-perf-router sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ca-perf-client ping -c 1 -W 1 198.51.100.2

sudo ip netns exec ca-perf-server iperf3 -s \
	>"$report_dir/iperf-server.log" 2>&1 &
iperf_pid=$!
ready=false
for attempt in $(seq 1 20); do
	if sudo ip netns exec ca-perf-server ss -lnt | grep -q ':5201 '; then
		ready=true
		break
	fi
	sleep 0.1
done
if [ "$ready" != true ]; then
	echo 'iperf3 server did not become ready' >&2
	exit 1
fi

sudo ip netns exec ca-perf-client iperf3 -c 198.51.100.2 \
	--time 3 --parallel 4 --json >"$report_dir/baseline.json"

sudo nsenter --net=/var/run/netns/ca-perf-router -- \
	"$controller" attach ca-perf-br
printf '%s\n' \
	'CONFIG 1 1 1 1 0 0 1 256 200 256 512 64' \
	'SUBJECT 02:00:00:00:00:42 42' \
	'POLICY 42 1 0' \
	'POLICY 42 0 0' \
	| sudo "$controller" sync
sudo nsenter --net=/var/run/netns/ca-perf-router -- \
	"$controller" health 1 1 ca-perf-br

sudo ip netns exec ca-perf-client iperf3 -c 198.51.100.2 \
	--time 3 --parallel 4 --json >"$report_dir/active.json"
sudo bpftool -j prog show pinned /sys/fs/bpf/client_access/ca_ingress \
	>"$report_dir/program.json"

sudo ip netns exec ca-perf-client bash -c '
	for port in $(seq 10000 28000); do
		echo full >"/dev/udp/198.51.100.2/${port}" || true
	done
'
sudo "$controller" status >"$report_dir/controller-status.json"
sudo bpftool -j map show pinned /sys/fs/bpf/client_access/ca_flows \
	>"$report_dir/flow-map-full.json"

jq -e '(.end.sum_received.bits_per_second // 0) > 0' \
	"$report_dir/baseline.json"
jq -e '(.end.sum_received.bits_per_second // 0) > 0' \
	"$report_dir/active.json"
jq -e '(if type == "array" then .[0] else . end | .run_cnt // 0) > 0' \
	"$report_dir/program.json"
jq -e '.flow_map_entries == .flow_capacity and .flow_map_full >= 1' \
	"$report_dir/controller-status.json"

jq -n \
	--slurpfile baseline "$report_dir/baseline.json" \
	--slurpfile active "$report_dir/active.json" \
	--slurpfile program "$report_dir/program.json" \
	--slurpfile flow_map_empty "$report_dir/flow-map-empty.json" \
	--slurpfile flow_map_full "$report_dir/flow-map-full.json" \
	--slurpfile status "$report_dir/controller-status.json" '
	def one($v): if ($v | type) == "array" then $v[0] else $v end;
	($baseline[0].end.sum_received.bits_per_second // 0) as $base |
	($active[0].end.sum_received.bits_per_second // 0) as $enabled |
	(one($program[0])) as $prog |
	(one($flow_map_empty[0])) as $empty_map |
	(one($flow_map_full[0])) as $full_map |
	{
	  environment: "GitHub-hosted ubuntu-24.04 x86_64 Linux bridge plus VLAN",
	  duration_seconds: 3,
	  parallel_streams: 4,
	  baseline_bits_per_second: $base,
	  application_filter_bits_per_second: $enabled,
	  observed_throughput_change_percent:
	    (if $base > 0 then (($enabled - $base) * 100 / $base) else null end),
	  bpf_run_count: ($prog.run_cnt // 0),
	  bpf_run_time_ns: ($prog.run_time_ns // 0),
	  average_bpf_run_time_ns:
	    (if ($prog.run_cnt // 0) > 0
	     then (($prog.run_time_ns // 0) / $prog.run_cnt) else null end),
	  empty_flow_map: $empty_map,
	  full_flow_map: $full_map,
	  observed_flow_map_memlock_growth_bytes:
	    (if (($empty_map.memlock // null) != null and
	         ($full_map.memlock // null) != null)
	     then ($full_map.memlock - $empty_map.memlock) else null end),
	  controller: $status[0],
	  interpretation:
	    "Informational shared-runner measurement; not an OpenWrt hardware claim or release threshold"
	}' >"$report_dir/summary.json"

cat "$report_dir/summary.json"
