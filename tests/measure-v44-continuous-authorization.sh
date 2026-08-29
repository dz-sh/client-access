#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

report_dir=$1
repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ruleset="$report_dir/client-access.nft"
capture="$report_dir/established-flow.txt"

cleanup() {
	if [ -n "${client_pid:-}" ]; then
		sudo kill "$client_pid" >/dev/null 2>&1 || true
	fi
	if [ -n "${server_pid:-}" ]; then
		sudo kill "$server_pid" >/dev/null 2>&1 || true
	fi
	if [ -n "${iperf_pid:-}" ]; then
		sudo kill "$iperf_pid" >/dev/null 2>&1 || true
	fi
	sudo ip netns del ca44-client >/dev/null 2>&1 || true
	sudo ip netns del ca44-server >/dev/null 2>&1 || true
	sudo ip netns del ca44-router >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$report_dir"
if command -v conntrack >/dev/null 2>&1; then
	echo 'V4.4 runtime job unexpectedly has conntrack-tools installed' >&2
	exit 1
fi

sudo ip netns add ca44-router
sudo ip netns add ca44-client
sudo ip netns add ca44-server
sudo ip link add ca44-lan type veth peer name ca44-client
sudo ip link add ca44-wan type veth peer name ca44-server
sudo ip link set ca44-lan netns ca44-router
sudo ip link set ca44-wan netns ca44-router
sudo ip link set ca44-client netns ca44-client
sudo ip link set ca44-server netns ca44-server

sudo ip netns exec ca44-router ip link set lo up
sudo ip netns exec ca44-router ip link set ca44-lan up
sudo ip netns exec ca44-router ip link set ca44-wan up
sudo ip netns exec ca44-router ip address add 192.0.2.1/24 dev ca44-lan
sudo ip netns exec ca44-router ip address add 198.51.100.1/24 dev ca44-wan
sudo ip netns exec ca44-router sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec ca44-client ip link set lo up
sudo ip netns exec ca44-client ip link set ca44-client \
	address 02:00:00:00:00:44
sudo ip netns exec ca44-client ip link set ca44-client up
sudo ip netns exec ca44-client ip address add 192.0.2.2/24 dev ca44-client
sudo ip netns exec ca44-client ip route add default via 192.0.2.1

sudo ip netns exec ca44-server ip link set lo up
sudo ip netns exec ca44-server ip link set ca44-server up
sudo ip netns exec ca44-server ip address add 198.51.100.2/24 dev ca44-server
sudo ip netns exec ca44-server ip route add 192.0.2.0/24 via 198.51.100.1

apply_ruleset() {
	mode=$1
	{
		echo 'table inet fw4 {'
		cat "$repo_dir/root/usr/share/nftables.d/table-pre/30-client-access.nft"
		echo 'chain forward {'
		echo 'type filter hook forward priority filter; policy accept;'
		if [ "$mode" = baseline ]; then
			sed 's/^iifname @client_access_sources/ct state { new, related } iifname @client_access_sources/' \
				"$repo_dir/root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft"
		else
			cat "$repo_dir/root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft"
		fi
		echo '}'
		echo '}'
	} >"$ruleset"
	sudo ip netns exec ca44-router nft delete table inet fw4 >/dev/null 2>&1 || true
	sudo ip netns exec ca44-router nft --file "$ruleset"
	sudo ip netns exec ca44-router nft add element inet fw4 \
		client_access_sources '{ "ca44-lan" }'
	sudo ip netns exec ca44-router nft add element inet fw4 \
		client_access_destinations '{ "ca44-wan" }'
}

sudo ip netns exec ca44-server iperf3 -s \
	>"$report_dir/iperf-server.log" 2>&1 &
iperf_pid=$!
ready=false
for attempt in $(seq 1 20); do
	if sudo ip netns exec ca44-server ss -lnt | grep -q ':5201 '; then
		ready=true
		break
	fi
	sleep 0.1
done
if [ "$ready" != true ]; then
	echo 'iperf3 server did not become ready' >&2
	exit 1
fi

apply_ruleset baseline
sudo ip netns exec ca44-client ping -c 1 -W 1 198.51.100.2
sudo ip netns exec ca44-client iperf3 -c 198.51.100.2 \
	--time 3 --parallel 4 --json >"$report_dir/new-related-only.json"

apply_ruleset continuous
sudo ip netns exec ca44-client iperf3 -c 198.51.100.2 \
	--time 3 --parallel 4 --json >"$report_dir/continuous.json"

sudo ip netns exec ca44-server sh -c \
	"nc -l -p 9000 > '$capture'" &
server_pid=$!
ready=false
for attempt in $(seq 1 20); do
	if sudo ip netns exec ca44-server ss -lnt | grep -q ':9000 '; then
		ready=true
		break
	fi
	sleep 0.1
done
if [ "$ready" != true ]; then
	echo 'established-flow TCP server did not become ready' >&2
	exit 1
fi
sudo ip netns exec ca44-client bash -c '
	exec 3<>/dev/tcp/198.51.100.2/9000
	printf "before-policy-change\n" >&3
	sleep 3
	printf "after-policy-change\n" >&3 || true
	sleep 1
' &
client_pid=$!

observed=false
for attempt in $(seq 1 30); do
	if grep -q '^before-policy-change$' "$capture" 2>/dev/null; then
		observed=true
		break
	fi
	sleep 0.1
done
if [ "$observed" != true ]; then
	echo 'established-flow precondition was not observed' >&2
	exit 1
fi

sudo ip netns exec ca44-router nft add element inet fw4 \
	client_access_exceptions '{ 02:00:00:00:00:44 }'
wait "$client_pid" || true
client_pid=
sudo kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" || true
server_pid=
grep -q '^before-policy-change$' "$capture"
if grep -q '^after-policy-change$' "$capture"; then
	echo 'established TCP flow bypassed the new V3 DENY policy' >&2
	exit 1
fi

sudo ip netns exec ca44-router nft list chain inet fw4 forward \
	>"$report_dir/continuous-forward-chain.txt"
if grep -Fq 'ct state' "$report_dir/continuous-forward-chain.txt"; then
	echo 'continuous V3 forwarding path still contains a conntrack-state gate' >&2
	exit 1
fi

jq -e '(.end.sum_received.bits_per_second // 0) > 0' \
	"$report_dir/new-related-only.json"
jq -e '(.end.sum_received.bits_per_second // 0) > 0' \
	"$report_dir/continuous.json"
jq -n \
	--slurpfile baseline "$report_dir/new-related-only.json" \
	--slurpfile continuous "$report_dir/continuous.json" '
	($baseline[0].end.sum_received.bits_per_second // 0) as $base |
	($continuous[0].end.sum_received.bits_per_second // 0) as $active |
	{
	  environment: "GitHub-hosted ubuntu-24.04 x86_64 routed veth",
	  duration_seconds: 3,
	  parallel_streams: 4,
	  new_related_only_bits_per_second: $base,
	  continuous_authorization_bits_per_second: $active,
	  observed_throughput_change_percent:
	    (if $base > 0 then (($active - $base) * 100 / $base) else null end),
	  established_tcp_allow_to_deny: "pass",
	  conntrack_tools_installed: false,
	  interpretation:
	    "Informational shared-runner measurement; investigate material changes, not an OpenWrt hardware threshold"
	}' >"$report_dir/summary.json"

cat "$report_dir/summary.json"
