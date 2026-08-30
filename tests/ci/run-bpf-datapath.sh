#!/bin/bash
set -euo pipefail

cleanup() {
  if [ -n "${udp_server_pid:-}" ]; then
    sudo kill "${udp_server_pid}" || true
  fi
  sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" detach ca-br-lan || true
  sudo ip netns exec ca-router-ns nft delete table inet fw4 || true
  sudo ip netns del ca-client-ns || true
  sudo ip netns del ca-server-ns || true
  sudo ip netns del ca-router-ns || true
  sudo "${RUNNER_TEMP}/client-access-bpfctl" unload || true
}
trap cleanup EXIT

sudo mkdir -p /sys/fs/bpf
if ! mountpoint --quiet /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
sudo "${RUNNER_TEMP}/client-access-bpfctl" load \
  "${RUNNER_TEMP}/client-access-bpf.o"

sudo ip netns add ca-router-ns
sudo ip netns add ca-client-ns
sudo ip netns add ca-server-ns
sudo ip link add ca-lan type veth peer name ca-client
sudo ip link add ca-wan type veth peer name ca-server
sudo ip link set ca-lan netns ca-router-ns
sudo ip link set ca-wan netns ca-router-ns
sudo ip link set ca-client netns ca-client-ns
sudo ip link set ca-server netns ca-server-ns
sudo ip netns exec ca-router-ns ip link set lo up
sudo ip netns exec ca-router-ns ip link add ca-br-lan type bridge
sudo ip netns exec ca-router-ns ip link add link ca-lan \
  name ca-lan.42 type vlan id 42
sudo ip netns exec ca-router-ns ip link set ca-lan up
sudo ip netns exec ca-router-ns ip link set ca-lan.42 master ca-br-lan
sudo ip netns exec ca-router-ns ip link set ca-lan.42 up
sudo ip netns exec ca-router-ns ip link set ca-br-lan up
sudo ip netns exec ca-router-ns ip link set ca-wan up
sudo ip netns exec ca-router-ns ip address add 192.0.2.1/24 dev ca-br-lan
sudo ip netns exec ca-router-ns ip address add 198.51.100.1/24 dev ca-wan
sudo ip netns exec ca-router-ns ip -6 address add \
  2001:db8:1::1/64 dev ca-br-lan nodad
sudo ip netns exec ca-router-ns ip -6 address add \
  2001:db8:2::1/64 dev ca-wan nodad
sudo ip netns exec ca-client-ns ip link set lo up
sudo ip netns exec ca-server-ns ip link set lo up
sudo ip netns exec ca-client-ns ip link set ca-client \
  address 02:00:00:00:00:42
sudo ip netns exec ca-server-ns ip link set ca-server \
  address 02:00:00:00:00:99
sudo ip netns exec ca-client-ns ip link set ca-client up
sudo ip netns exec ca-client-ns ip link add link ca-client \
  name ca-client.42 type vlan id 42
sudo ip netns exec ca-client-ns ip link set ca-client.42 up
sudo ip netns exec ca-server-ns ip link set ca-server up
sudo ip netns exec ca-client-ns ip address add \
  192.0.2.2/24 dev ca-client.42
sudo ip netns exec ca-server-ns ip address add \
  198.51.100.2/24 dev ca-server
sudo ip netns exec ca-server-ns ip address add \
  198.51.100.3/24 dev ca-server
sudo ip netns exec ca-server-ns ip address add \
  198.51.100.4/24 dev ca-server
sudo ip netns exec ca-client-ns ip -6 address add \
  2001:db8:1::2/64 dev ca-client.42 nodad
sudo ip netns exec ca-server-ns ip -6 address add \
  2001:db8:2::2/64 dev ca-server nodad
sudo ip netns exec ca-client-ns ip route add default via 192.0.2.1
sudo ip netns exec ca-server-ns ip route add 192.0.2.0/24 via 198.51.100.1
sudo ip netns exec ca-client-ns ip -6 route add default via 2001:db8:1::1
sudo ip netns exec ca-server-ns ip -6 route add 2001:db8:1::/64 via 2001:db8:2::1
sudo ip netns exec ca-router-ns sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ca-router-ns sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip netns exec ca-router-ns ip neigh replace 198.51.100.2 \
  lladdr 02:00:00:00:00:99 dev ca-wan nud permanent
sudo ip netns exec ca-router-ns ip neigh replace 198.51.100.3 \
  lladdr 02:00:00:00:00:99 dev ca-wan nud permanent
sudo ip netns exec ca-router-ns ip neigh replace 198.51.100.4 \
  lladdr 02:00:00:00:00:99 dev ca-wan nud permanent
sudo ip netns exec ca-router-ns ip -6 neigh replace 2001:db8:2::2 \
  lladdr 02:00:00:00:00:99 dev ca-wan nud permanent
sudo ip netns exec ca-server-ns nc -u -l -k 443 >/dev/null &
udp_server_pid=$!
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan

# Exercise the pinned-object lifecycle in the namespace that owns
# the TC attachment. Ensure is idempotent, load detaches the old
# owned program before replacing its ABI, and unload removes both
# the attachment and all pins.
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" ensure \
  "${RUNNER_TEMP}/client-access-bpf.o"
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" load \
  "${RUNNER_TEMP}/client-access-bpf.o"
if sudo ip netns exec ca-router-ns tc -j filter show dev ca-br-lan ingress \
    | jq -e 'any(.[]; .kind == "bpf")' >/dev/null; then
  echo 'load left the replaced TC program attached' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" unload
if sudo ip netns exec ca-router-ns tc -j filter show dev ca-br-lan ingress \
    | jq -e 'any(.[]; .kind == "bpf")' >/dev/null; then
  echo 'unload left the owned TC program attached' >&2
  exit 1
fi
if sudo "${RUNNER_TEMP}/client-access-bpfctl" status; then
  echo 'unload left a usable pinned backend' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" ensure \
  "${RUNNER_TEMP}/client-access-bpf.o"
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan

# A partial current pin set is recovered as a complete unit,
# detaching the old owned program first.
sudo rm /sys/fs/bpf/client_access/ca_policy_a
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" ensure \
  "${RUNNER_TEMP}/client-access-bpf.o"
if sudo ip netns exec ca-router-ns tc -j filter show dev ca-br-lan ingress \
    | jq -e 'any(.[]; .kind == "bpf")' >/dev/null; then
  echo 'partial backend replacement left the old program attached' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan
# V41-LIFE-004/005: a foreign program at the reserved coordinate is
# neither replaced by attach nor removed by detach.
sudo bpftool prog load "${RUNNER_TEMP}/foreign-tc-bpf.o" \
  /sys/fs/bpf/ca-foreign-tc type classifier
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  tc qdisc add dev ca-wan clsact
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  tc filter add dev ca-wan ingress \
  protocol all pref 202 handle 202 bpf direct-action \
  pinned /sys/fs/bpf/ca-foreign-tc
if sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" attach ca-wan; then
  echo 'attach replaced a foreign TC program' >&2
  exit 1
fi
if sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" detach ca-wan; then
  echo 'detach removed or accepted a foreign TC program' >&2
  exit 1
fi
sudo ip netns exec ca-router-ns tc -j filter show dev ca-wan ingress \
  | jq -e 'any(.[]; .kind == "bpf")' >/dev/null
sudo ip netns exec ca-router-ns tc filter del dev ca-wan ingress \
  pref 202 handle 202 bpf
sudo rm /sys/fs/bpf/ca-foreign-tc

# A daemon restart loses its in-memory attachment list. Pruning by
# pinned program ID keeps the desired interface and removes only a
# stale attachment owned by this application.
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-wan
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" prune ca-br-lan
sudo ip netns exec ca-router-ns tc -j filter show dev ca-br-lan ingress \
  | jq -e 'any(.[]; .kind == "bpf")' >/dev/null
if sudo ip netns exec ca-router-ns tc -j filter show dev ca-wan ingress \
    | jq -e 'any(.[]; .kind == "bpf")' >/dev/null; then
  echo 'prune left a stale owned TC program attached' >&2
  exit 1
fi

# Establish that the namespace router works before adding the
# application workflow's nft forward consumer.
sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2
sudo ip netns exec ca-client-ns ping -6 -c 1 -W 1 2001:db8:2::2

{
  echo 'table inet fw4 {'
  cat root/usr/share/nftables.d/table-pre/30-client-access.nft
  echo 'chain forward {'
  echo 'type filter hook forward priority filter; policy accept;'
  cat root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft
  echo '}'
  echo '}'
} > "${RUNNER_TEMP}/client-access-runtime.nft"
sudo ip netns exec ca-router-ns nft \
  --file "${RUNNER_TEMP}/client-access-runtime.nft"
sudo ip netns exec ca-router-ns nft add element inet fw4 \
  client_access_app_sources '{ "ca-br-lan" }'
sudo ip netns exec ca-router-ns nft add element inet fw4 \
  client_access_app_destinations '{ "ca-wan" }'

# Installing the app-only consumer must remain neutral while the
# BPF application snapshot is disabled.
if ! sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2; then
  sudo ip netns exec ca-router-ns ip -details route show
  sudo ip netns exec ca-router-ns tc -s filter show dev ca-br-lan ingress
  sudo ip netns exec ca-router-ns nft -a list ruleset
  sudo "${RUNNER_TEMP}/client-access-bpfctl" status || true
  exit 1
fi
sudo ip netns exec ca-client-ns ping -6 -c 1 -W 1 2001:db8:2::2

# V42-TEST-010: client-accessd is intentionally absent from this
# job. Forwarding and classification use the last complete snapshot
# without waiting for a userspace Classification Engine.
printf '%s\n' \
  'CONFIG 1 1 1 1 0 0 1 256 200 256 512 64' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'PREFIX4 198.51.100.2/32 100 10 1' \
  'PREFIX6 2001:db8:2::2/128 100 10 1' \
  'PORT 17 443 10 10 2' \
  'POLICY 42 100 1' \
  'POLICY 42 10 1' \
  'POLICY 42 1 1' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan
if sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" health 2 1 ca-br-lan; then
  echo 'health accepted a stale application-policy generation' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" detach ca-br-lan
if sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan; then
  echo 'health accepted a missing expected TC attachment' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-br-lan
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan

# V41-LIFE-003: multi-object reads and GC contend on the same
# controller lock without exposing a partial runtime snapshot.
pids=''
for attempt in $(seq 1 8); do
  sudo "${RUNNER_TEMP}/client-access-bpfctl" status >/dev/null &
  pids="${pids} $!"
  sudo "${RUNNER_TEMP}/client-access-bpfctl" generations >/dev/null &
  pids="${pids} $!"
  sudo "${RUNNER_TEMP}/client-access-bpfctl" gc 86400 >/dev/null &
  pids="${pids} $!"
done
for pid in ${pids}; do
  wait "${pid}"
done
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan

# Health describes the exact owned attachment set, not merely a
# minimum list of interfaces that must contain the program.
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" attach ca-wan
if sudo nsenter --net=/var/run/netns/ca-router-ns -- \
    "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan; then
  echo 'health accepted an extra owned TC attachment' >&2
  exit 1
fi
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" prune ca-br-lan
sudo nsenter --net=/var/run/netns/ca-router-ns -- \
  "${RUNNER_TEMP}/client-access-bpfctl" health 1 1 ca-br-lan

# Router-local traffic is outside the app-filter workflow.
# The second packet has a cached UNCLASSIFIED DENY app verdict but
# must still bypass the forward-only nft application chain.
sudo ip netns exec ca-client-ns ping -c 2 -W 1 192.0.2.1

# Port-only evidence resolves only the category and is cached for
# the second datagram on the same socket.
sudo ip netns exec ca-client-ns bash -c \
  'exec 3>/dev/udp/198.51.100.3/443; echo first >&3; echo second >&3'

# The first packet has the explicit provisional ALLOW; the cached
# exact-application verdict drops the next packet.
sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2
if sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2; then
  echo 'cached exact-application DENY did not drop the second packet' >&2
  exit 1
fi
sudo ip netns exec ca-client-ns ping -6 -c 1 -W 1 2001:db8:2::2
if sudo ip netns exec ca-client-ns ping -6 -c 1 -W 1 2001:db8:2::2; then
  echo 'IPv6 exact-application DENY did not drop the second packet' >&2
  exit 1
fi

printf '%s\n' \
  'CONFIG 1 1 2 1 0 0 1 256 200 256 512 64' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'PREFIX4 198.51.100.2/32 100 10 1' \
  'PREFIX6 2001:db8:2::2/128 100 10 1' \
  'PORT 17 443 10 10 2' \
  'POLICY 42 100 0' \
  'POLICY 42 10 1' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
# Policy-generation mismatch reuses the exact class and allows the
# existing flow without reopening provisional classification.
sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2

# V41-FLOW-008: classifier generation changes apply to new flows.
# The existing ICMP flow keeps class 100, while a different source
# address creates a new flow and observes the new class 101 mapping.
printf '%s\n' \
  'CONFIG 1 1 3 2 0 0 1 256 200 256 512 64' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'PREFIX4 198.51.100.2/32 101 10 1' \
  'POLICY 42 100 0' \
  'POLICY 42 101 1' \
  'POLICY 42 10 0' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.2
sudo ip netns exec ca-client-ns ip address add \
  192.0.2.3/24 dev ca-client.42
sudo ip netns exec ca-client-ns ping -I 192.0.2.3 -c 1 -W 1 \
  198.51.100.2
if sudo ip netns exec ca-client-ns ping -I 192.0.2.3 -c 1 -W 1 \
    198.51.100.2; then
  echo 'new flow ignored the new classifier generation' >&2
  exit 1
fi

# A failed inactive-slot build must leave generation 3 active.
if printf '%s\n' \
    'CONFIG 1 1 4 2 0 0 1 256 200 256 512 64' \
    'SUBJECT 02:00:00:00:00:42 42' \
    'SUBJECT 02:00:00:00:00:42 42' \
    | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync; then
  echo 'invalid atomic snapshot unexpectedly succeeded' >&2
  exit 1
fi

# V4.2 userspace has already fused Profile and Observation evidence.
# The datapath receives only the complete near-final projection:
# one exact result and one deterministic UNCLASSIFIED conflict.
printf '%s\n' \
  'CONFIG 1 1 4 2 0 0 1 256 200 256 512 64' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'PREFIX4 198.51.100.3/32 101 10 1' \
  'PREFIX4 198.51.100.4/32 1 0 3' \
  'PORT 17 443 10 10 2' \
  'POLICY 42 101 1' \
  'POLICY 42 10 1' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.3
if sudo ip netns exec ca-client-ns ping -c 1 -W 1 198.51.100.3; then
  echo 'precomputed exact application DENY did not become terminal' >&2
  exit 1
fi
sudo ip netns exec ca-client-ns ping -c 2 -W 1 198.51.100.4

# Fragmented packets have no supported canonical flow key in V4.1.
# They receive the independent UNCLASSIFIED app verdict immediately
# and remain per-packet bounded rather than entering flow state.
printf '%s\n' \
  'CONFIG 1 1 5 2 0 0 1 256 200 256 512 64' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'POLICY 42 1 1' \
  'POLICY 42 0 1' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
if sudo ip netns exec ca-client-ns ping -c 1 -W 1 -s 2000 \
    198.51.100.3; then
  echo 'fragmented IPv4 unexpectedly bypassed UNCLASSIFIED DENY' >&2
  exit 1
fi
if sudo ip netns exec ca-client-ns ping -6 -c 1 -W 1 -s 2000 \
    2001:db8:2::2; then
  echo 'fragmented IPv6 unexpectedly bypassed UNCLASSIFIED DENY' >&2
  exit 1
fi
router_mac=$(sudo ip netns exec ca-router-ns \
  cat /sys/class/net/ca-br-lan/address)
parse_before=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.parse_unsupported')
malformed_count=$(sudo ip netns exec ca-client-ns python3 \
  tests/send-malformed-frames.py ca-client.42 "${router_mac}")
parse_after=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.parse_unsupported')
# Every frame in the AF_PACKET-reachable adversarial corpus must take
# the explicit unsupported path.
malformed_delta=$((parse_after - parse_before))
if test "${malformed_delta}" -ne "${malformed_count}"; then
  echo "malformed parser count mismatch: expected=${malformed_count} observed=${malformed_delta}" >&2
  exit 1
fi

# V41-SEC-002: isolate per-subject admission pressure from the
# higher global limit.
sleep 1.1
printf '%s\n' \
  'CONFIG 1 1 6 2 0 0 1 256 200 256 100 1' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
admission_before=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
sudo ip netns exec ca-client-ns bash -c '
  for port in $(seq 5000 5031); do
    echo pressure >"/dev/udp/198.51.100.3/${port}" || true
  done
'
admission_after=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
test "$((admission_after - admission_before))" -ge 30

# Isolate global admission pressure while the per-subject allowance
# is high enough not to be the limiting dimension.
sleep 1.1
printf '%s\n' \
  'CONFIG 1 1 7 2 0 0 1 256 200 256 1 100' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
admission_before=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
sudo ip netns exec ca-client-ns bash -c '
  for port in $(seq 6000 6031); do
    echo pressure >"/dev/udp/198.51.100.3/${port}" || true
  done
'
admission_after=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
test "$((admission_after - admission_before))" -ge 30

# Force the bounded pending counter to its configured ceiling, then
# prove that a new flow is load-shed without entering classification.
sleep 1.1
printf '%s\n' \
  'CONFIG 1 1 8 2 0 0 1 256 200 1 100 100' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
sudo bpftool map update pinned /sys/fs/bpf/client_access/ca_runtime \
  key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00
admission_before=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
sudo ip netns exec ca-client-ns bash -c \
  'echo pending > /dev/udp/198.51.100.3/7000'
admission_after=$(sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | jq -r '.classification_admission_denied')
test "$((admission_after - admission_before))" -ge 1
sudo bpftool map update pinned /sys/fs/bpf/client_access/ca_runtime \
  key hex 00 00 00 00 value hex 00 00 00 00 01 00 00 00

# The fixed-capacity HASH deliberately refuses excess flow state;
# it must not evict an active terminal flow and reopen leakage.
sleep 1.1
printf '%s\n' \
  'CONFIG 1 1 9 2 0 0 1 256 200 256 100000 100000' \
  'SUBJECT 02:00:00:00:00:42 42' \
  'POLICY 42 1 0' \
  'POLICY 42 0 0' \
  | sudo "${RUNNER_TEMP}/client-access-bpfctl" sync
sudo ip netns exec ca-client-ns bash -c '
  for port in $(seq 10000 28000); do
    echo full >"/dev/udp/198.51.100.3/${port}" || true
  done
'

sudo "${RUNNER_TEMP}/client-access-bpfctl" status \
  | tee "${RUNNER_TEMP}/client-access-bpf-status.json"
jq -e '
  .enabled == true and
  .bpf_schema_version == 5 and
  .app_policy_generation == 9 and
  .classifier_generation == 2 and
  .subject_entries == 1 and
  .policy_entries == 2 and
  .flow_map_entries >= 4 and
  .flows_classified_exact >= 3 and
  .flows_classified_category >= 1 and
  .flow_app_deny_verdicts >= 1 and
  .flow_app_allow_verdicts >= 1 and
  .packet_app_deny_verdicts >= 1 and
  .classification_admission_denied >= 1 and
  .flows_unclassified_load_shed >= 1 and
  .flows_unclassified >= .flows_unclassified_load_shed and
  .flow_map_entries == .flow_capacity and
  .flow_map_full >= 1 and
  .flow_map_evictions == 0 and
  .parse_unsupported >= 18 and
  .policy_reevaluations >= 1
' "${RUNNER_TEMP}/client-access-bpf-status.json"
