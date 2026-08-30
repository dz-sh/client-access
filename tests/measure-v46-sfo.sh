#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

object=${1:?usage: measure-v46-sfo.sh BPF_OBJECT BPFCTL SFOCTL REPORT_DIR}
bpfctl=${2:?usage: measure-v46-sfo.sh BPF_OBJECT BPFCTL SFOCTL REPORT_DIR}
sfoctl=${3:?usage: measure-v46-sfo.sh BPF_OBJECT BPFCTL SFOCTL REPORT_DIR}
report_dir=${4:?usage: measure-v46-sfo.sh BPF_OBJECT BPFCTL SFOCTL REPORT_DIR}
repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
router_ns=ca46-router
client_ns=ca46-client
server_ns=ca46-server
current_phase=initialization

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		printf 'V4.6 SFO measurement failed during: %s\n' "$current_phase" >&2
		printf '%s\n' "$current_phase" >"$report_dir/failed-phase.txt" 2>/dev/null || true
	fi
	for pid in ${flow_pids:-}; do
		sudo kill "$pid" >/dev/null 2>&1 || true
	done
	if [ -e "/var/run/netns/$server_ns" ]; then
		sudo ip netns exec "$server_ns" pkill iperf3 >/dev/null 2>&1 || true
	fi
	if [ -e "/var/run/netns/$router_ns" ]; then
		sudo nsenter --net="/var/run/netns/$router_ns" -- \
			"$bpfctl" detach ca46-lan >/dev/null 2>&1 || true
	fi
	sudo ip netns del "$client_ns" >/dev/null 2>&1 || true
	sudo ip netns del "$server_ns" >/dev/null 2>&1 || true
	sudo ip netns del "$router_ns" >/dev/null 2>&1 || true
	sudo "$bpfctl" unload >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$report_dir"
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
sudo mkdir -p /sys/fs/bpf
if ! mountpoint --quiet /sys/fs/bpf; then
	sudo mount -t bpf bpf /sys/fs/bpf
fi

sudo "$bpfctl" load "$object"
current_phase=network_namespace_setup
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
sudo ip netns add "$router_ns"
sudo ip netns add "$client_ns"
sudo ip netns add "$server_ns"
sudo ip link add ca46-lan type veth peer name ca46-client
sudo ip link add ca46-wan type veth peer name ca46-server
sudo ip link set ca46-lan netns "$router_ns"
sudo ip link set ca46-wan netns "$router_ns"
sudo ip link set ca46-client netns "$client_ns"
sudo ip link set ca46-server netns "$server_ns"

sudo ip netns exec "$router_ns" ip link set lo up
sudo ip netns exec "$router_ns" ip link set ca46-lan up
sudo ip netns exec "$router_ns" ip link set ca46-wan up
sudo ip netns exec "$router_ns" ip address add 192.0.2.1/24 dev ca46-lan
sudo ip netns exec "$router_ns" ip address add 198.51.100.1/24 dev ca46-wan
sudo ip netns exec "$router_ns" ip -6 address add fd46:1::1/64 dev ca46-lan nodad
sudo ip netns exec "$router_ns" ip -6 address add fd46:2::1/64 dev ca46-wan nodad
sudo ip netns exec "$router_ns" sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec "$router_ns" sysctl -w net.ipv6.conf.all.forwarding=1

sudo ip netns exec "$client_ns" ip link set lo up
sudo ip netns exec "$client_ns" ip link set ca46-client address 02:00:00:00:00:46
sudo ip netns exec "$client_ns" ip link set ca46-client up
sudo ip netns exec "$client_ns" ip address add 192.0.2.2/24 dev ca46-client
sudo ip netns exec "$client_ns" ip -6 address add fd46:1::2/64 dev ca46-client nodad
sudo ip netns exec "$client_ns" ip route add default via 192.0.2.1
sudo ip netns exec "$client_ns" ip -6 route add default via fd46:1::1

sudo ip netns exec "$server_ns" ip link set lo up
sudo ip netns exec "$server_ns" ip link set ca46-server up
sudo ip netns exec "$server_ns" ip address add 198.51.100.2/24 dev ca46-server
sudo ip netns exec "$server_ns" ip -6 address add fd46:2::2/64 dev ca46-server nodad
sudo ip netns exec "$server_ns" ip route add 192.0.2.0/24 via 198.51.100.1
sudo ip netns exec "$server_ns" ip -6 route add fd46:1::/64 via fd46:2::1

apply_ruleset() {
	mode=$1
	{
		printf '%s\n' 'table inet fw4 {'
		if [ "$mode" = sfo ]; then
			printf '%s\n' \
				'flowtable ft {' \
				' hook ingress priority filter' \
				' devices = { ca46-lan, ca46-wan }' \
				'}'
		fi
		printf '%s\n' \
			'chain forward {' \
			' type filter hook forward priority filter; policy drop;' \
			' meta mark & 0x60000000 == 0x60000000 drop'
		if [ "$mode" = sfo ]; then
			printf '%s\n' ' meta l4proto { tcp, udp } flow offload @ft'
		fi
		printf '%s\n' \
			' ct state established,related accept' \
			' iifname "ca46-lan" oifname "ca46-wan" accept' \
			'}' \
			'}' \
			'table ip ca46_nat {' \
			'chain postrouting {' \
			' type nat hook postrouting priority srcnat; policy accept;' \
			' oifname "ca46-wan" masquerade' \
			'}' \
			'}'
	} >"$report_dir/fw4-$mode.nft"
	sudo ip netns exec "$router_ns" nft delete table inet fw4 >/dev/null 2>&1 || true
	sudo ip netns exec "$router_ns" nft delete table ip ca46_nat >/dev/null 2>&1 || true
	sudo ip netns exec "$router_ns" nft -f "$report_dir/fw4-$mode.nft"
}

publish() {
	generation=$1
	class10=$2
	class20=$3
	class30=$4
	class40=$5
	class50=$6
	{
		printf 'CONFIG 1 1 %s 1 0 0 1 256 200 4096 100000 100000\n' "$generation"
		printf '%s\n' 'SUBJECT 02:00:00:00:00:46 42'
		printf 'POLICY 42 10 %s\n' "$class10"
		printf 'POLICY 42 20 %s\n' "$class20"
		printf 'POLICY 42 30 %s\n' "$class30"
		printf 'POLICY 42 40 %s\n' "$class40"
		printf 'POLICY 42 50 %s\n' "$class50"
		printf '%s\n' 'POLICY 42 1 0' 'POLICY 42 0 0'
		printf '%s\n' \
			'PORT 6 5201 10 0 1' \
			'PORT 6 5202 20 0 1' \
			'PORT 6 5203 30 0 1' \
			'PORT 6 5204 40 0 1' \
			'PORT 17 5204 40 0 1' \
			'PORT 6 5206 20 0 1' \
			'PORT 6 5210 50 0 1'
	} | sudo "$bpfctl" sync
}

wait_for_offload() {
	minimum=$1
	output=$2
	for attempt in $(seq 1 80); do
		if sudo ip netns exec "$router_ns" "$sfoctl" status >"$output" &&
		   jq -e --argjson minimum "$minimum" \
			'.result == "COMPLETE" and .software_offloaded_flow_count >= $minimum' \
			"$output" >/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	echo "software flow offload did not reach $minimum entries" >&2
	return 1
}

for port in 5201 5202 5203 5204 5206; do
	sudo ip netns exec "$server_ns" iperf3 -s -D -p "$port"
done
current_phase=connectivity_probe
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
sudo ip netns exec "$client_ns" ping -c 1 -W 1 198.51.100.2 >/dev/null
sudo ip netns exec "$client_ns" ping -6 -c 1 -W 1 fd46:2::2 >/dev/null

current_phase=normal_and_sfo_throughput
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
apply_ruleset normal
sudo ip netns exec "$client_ns" iperf3 -c 198.51.100.2 -p 5206 \
	-t 3 -P 2 -J >"$report_dir/baseline.json"

sudo nsenter --net="/var/run/netns/$router_ns" -- "$bpfctl" attach ca46-lan
publish 1 0 0 0 0 0
sudo ip netns exec "$client_ns" iperf3 -c 198.51.100.2 -p 5206 \
	-t 3 -P 2 -J >"$report_dir/ca-normal.json"

apply_ruleset sfo
sudo ip netns exec "$client_ns" iperf3 -c 198.51.100.2 -p 5206 \
	-t 3 -P 2 -J >"$report_dir/ca-sfo.json"
wait_for_offload 1 "$report_dir/actual-sfo.json"

current_phase=targeted_revocation
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
sudo ip netns exec "$client_ns" iperf3 -c 198.51.100.2 -p 5201 \
	-t 30 -P 4 -J >"$report_dir/class10-flow.json" 2>&1 &
flow10_pid=$!
sudo ip netns exec "$client_ns" iperf3 -c 198.51.100.2 -p 5202 \
	-t 30 -P 4 -J >"$report_dir/class20-flow.json" 2>&1 &
flow20_pid=$!
flow_pids="$flow10_pid $flow20_pid"
wait_for_offload 2 "$report_dir/two-class-sfo.json"
publish 2 1 0 0 0 0
sudo ip netns exec "$router_ns" "$sfoctl" revoke 42 10 2000 \
	>"$report_dir/ipv4-nat-class-revocation.json"
jq -e '.result == "COMPLETE" and .candidate_count >= 4 and .remaining == 0 and
	.revocation_latency_ms <= 2000' "$report_dir/ipv4-nat-class-revocation.json"
sudo kill -0 "$flow20_pid"

sudo ip netns exec "$client_ns" iperf3 -6 -c fd46:2::2 -p 5203 \
	-t 30 -J >"$report_dir/ipv6-flow.json" 2>&1 &
flow30_pid=$!
flow_pids="$flow_pids $flow30_pid"
wait_for_offload 2 "$report_dir/ipv6-sfo.json"
publish 3 1 0 1 0 0
sudo ip netns exec "$router_ns" "$sfoctl" revoke 42 30 2000 \
	>"$report_dir/ipv6-class-revocation.json"
jq -e '.result == "COMPLETE" and .candidate_count >= 1 and .remaining == 0 and
	.revocation_latency_ms <= 2000' "$report_dir/ipv6-class-revocation.json"
sudo kill -0 "$flow20_pid"

sudo ip netns exec "$client_ns" iperf3 -u -c 198.51.100.2 -p 5204 \
	-b 20M -t 30 -J >"$report_dir/udp-flow.json" 2>&1 &
flow40_pid=$!
flow_pids="$flow_pids $flow40_pid"
wait_for_offload 2 "$report_dir/udp-sfo.json"
publish 4 1 0 1 1 0
sudo ip netns exec "$router_ns" "$sfoctl" revoke 42 40 2000 \
	>"$report_dir/udp-class-revocation.json"
jq -e '.result == "COMPLETE" and .candidate_count >= 1 and .remaining == 0 and
	.revocation_latency_ms <= 2000' "$report_dir/udp-class-revocation.json"
sudo kill -0 "$flow20_pid"

sudo ip netns exec "$router_ns" "$sfoctl" revoke 42 - 2000 \
	>"$report_dir/subject-revocation.json"
jq -e '.result == "COMPLETE" and .candidate_count >= 1 and .remaining == 0 and
	.revocation_latency_ms <= 2000' "$report_dir/subject-revocation.json"

current_phase=near_candidate_bound
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
stress_count=3072
sudo ip netns exec "$server_ns" sh -c \
	"ulimit -n 8192; exec python3 '$repo_dir/tests/sfo-flow-load.py' server 198.51.100.2 5210 $stress_count" \
	>"$report_dir/stress-server.log" 2>&1 &
stress_server_pid=$!
flow_pids="$flow_pids $stress_server_pid"
sudo ip netns exec "$client_ns" sh -c \
	"ulimit -n 8192; exec python3 '$repo_dir/tests/sfo-flow-load.py' client 198.51.100.2 5210 $stress_count" \
	>"$report_dir/stress-client.log" 2>&1 &
stress_client_pid=$!
flow_pids="$flow_pids $stress_client_pid"
stress_ready=false
for attempt in $(seq 1 300); do
	if grep -q "^READY $stress_count$" "$report_dir/stress-client.log"; then
		stress_ready=true
		break
	fi
	sleep 0.1
done
if [ "$stress_ready" != true ]; then
	echo 'near-bound candidate flow load did not become ready' >&2
	exit 1
fi
wait_for_offload 100 "$report_dir/stress-sfo.json"
sudo "$bpfctl" status >"$report_dir/stress-bpf-status.json"
jq -e --argjson minimum "$stress_count" '.flow_map_entries >= $minimum' \
	"$report_dir/stress-bpf-status.json"
publish 5 1 0 1 1 1
sudo ip netns exec "$router_ns" "$sfoctl" revoke 42 50 10000 \
	>"$report_dir/near-bound-revocation.json"
jq -e --argjson minimum "$stress_count" \
	'.result == "COMPLETE" and .candidate_count >= $minimum and .remaining == 0 and
	.revocation_latency_ms <= 10000' "$report_dir/near-bound-revocation.json"

sudo ip netns exec "$router_ns" "$sfoctl" gc 1 \
	>"$report_dir/offload-aware-gc.json"
jq -e '.result == "COMPLETE" and .correlation_health == "HEALTHY"' \
	"$report_dir/offload-aware-gc.json"

current_phase=summary
printf '%s\n' "$current_phase" >"$report_dir/phase.txt"
jq -n \
	--slurpfile baseline "$report_dir/baseline.json" \
	--slurpfile normal "$report_dir/ca-normal.json" \
	--slurpfile sfo "$report_dir/ca-sfo.json" \
	--slurpfile active "$report_dir/actual-sfo.json" \
	--slurpfile v4 "$report_dir/ipv4-nat-class-revocation.json" \
	--slurpfile v6 "$report_dir/ipv6-class-revocation.json" \
	--slurpfile udp "$report_dir/udp-class-revocation.json" \
	--slurpfile subject "$report_dir/subject-revocation.json" \
	--slurpfile stress "$report_dir/near-bound-revocation.json" '
	{
	  environment: "GitHub-hosted Ubuntu 24.04 routed veth with IPv4 masquerade and IPv6",
	  throughput_bits_per_second: {
	    baseline: ($baseline[0].end.sum_received.bits_per_second // 0),
	    ca_normal: ($normal[0].end.sum_received.bits_per_second // 0),
	    ca_sfo: ($sfo[0].end.sum_received.bits_per_second // 0)
	  },
	  actual_software_offloaded_flows: $active[0].software_offloaded_flow_count,
	  revocation_latency_ms: {
	    ipv4_nat_tcp_class: $v4[0].revocation_latency_ms,
	    ipv6_tcp_class: $v6[0].revocation_latency_ms,
	    ipv4_udp_class: $udp[0].revocation_latency_ms,
	    subject: $subject[0].revocation_latency_ms,
	    near_candidate_bound: $stress[0].revocation_latency_ms
	  },
	  near_candidate_bound_count: $stress[0].candidate_count,
	  unrelated_flow_preserved_during_class_revocation: true,
	  deadline_ms: 2000,
	  interpretation: "Shared-runner functional and informational performance evidence; not a router hardware throughput claim"
	}' >"$report_dir/summary.json"

jq -e '.throughput_bits_per_second.baseline > 0 and
	.throughput_bits_per_second.ca_normal > 0 and
	.throughput_bits_per_second.ca_sfo > 0 and
	.actual_software_offloaded_flows > 0' "$report_dir/summary.json"
cat "$report_dir/summary.json"
