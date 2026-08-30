# luci-app-client-access

An OpenWrt/ImmortalWrt LuCI application for discovering LAN clients and
controlling their Internet access with firewall4/nftables.

## Features

- Discover LAN clients with best-effort names and IP addresses.
- Create stable identities for the clients you want to manage.
- Associate multiple MAC addresses with one identity.
- Choose one global policy: off, block selected clients, or allow selected
  clients.
- Choose whether the policy applies to an identity never, always, or on a
  weekly schedule.
- Use one or more periods per day, different periods on different weekdays, and
  periods that cross midnight.
- Control IPv4 and IPv6 forwarding without creating one nftables rule per
  client.
- Optionally add independent, best-effort application rules based on domains,
  IP prefixes, protocol, and destination ports.
- Temporarily approve a blocked identity or blocked application/category for
  one hour or until local midnight, then automatically restore the saved
  policy.
- Optionally keep canonical firewall4 software flow offload enabled with
  bounded, verified revocation after restrictive policy changes.

## Internet access policy

Access control is disabled by default.

| Policy | Unselected and unknown clients | Selected identities |
| --- | --- | --- |
| Off | Allowed | Allowed |
| Block selected clients | Allowed | Blocked |
| Allow selected clients | Blocked | Allowed |

Changing between the two enabled policies reverses the result for both selected
and unselected clients.

## Identities and unknown clients

The application separates discovered clients from identities:

- **Unknown clients** are temporary observations which have not been assigned
  to an identity. They follow the global default policy and are not scheduled.
- **Managed identities** are clients you have explicitly created and named.
  Their recognized MAC addresses and weekly periods are persistent. Detected
  names and IP addresses are shown with the corresponding recognized MAC.

From **Unknown**, you can either manage a detected MAC as a new identity or add
it to an existing identity. Creating an identity defaults to **Never**, so the
operation does not silently change Internet access. Private MAC addresses are
never merged automatically.

An identity can be:

- **Never** — the selected policy does not apply; follow the global default.
- **Always** — the selected policy always applies.
- **On schedule** — the selected policy applies while a weekly period matches.

## Weekly schedules

The identity editor provides a separate list of periods for each weekday. Add
multiple periods to the same day when needed, use `all-day` for the entire day,
or enter a period such as `22:00-07:00` to end on the following day. Times use
the router's local timezone with one-minute resolution.

## Optional application filtering

Application filtering is off by default and requires the optional
`client-access-bpf` package. Define applications or broad categories, add
bounded classification evidence, then attach allow or block rules to an
identity. Application rules have their own always, never, or weekly schedule
and remain independent from the global nftables policy.

Application knowledge is stored as reusable Profiles, independently from
identity access rules. Classification complexity belongs in userspace. The
datapath consumes precomputed classification state. A datapath miss MUST NOT
invoke a userspace classification slow path.

Application classification remains best effort: it allows packets in a small initial window while
classifying one early packet of a new flow, uses bounded DNS/IP/port evidence
rather than full DPI, and treats ambiguous or encrypted traffic as
unclassified. LuCI reports classification coverage and resource shedding.

Canonical firewall4 software flow offload is supported when both
`client-access-bpf` and `client-access-sfo` are installed. Restrictive changes
publish policy first and then remove and verify matching accelerated flows
within a configured deadline. This is bounded revocation, not instant or
zero-packet termination. Hardware and custom flow-offload paths remain
unsupported.

## Temporary approvals

Temporary approvals are runtime-only ALLOW overrides. They do not edit saved
identity policy, application rules, or weekly schedules. A blocked identity or
application/category can be approved for one hour or until the end of the
router's local day, extended by choosing another duration, or revoked
immediately. LuCI shows the base result, expiry, remaining time, and effective
result separately.

Active approvals survive a service restart through volatile runtime state, but
intentionally disappear after a router reboot. Default and unclassified
application traffic cannot receive a temporary approval.

## Usage

For the normal web interface, install `luci-app-client-access`; it installs the
headless `client-access-core` runtime automatically. A router managed without
LuCI can install `client-access-core` directly. Install `client-access-bpf` for
application filtering. To use canonical firewall4 software flow offload,
install `client-access-sfo`; it also installs the BPF correlation backend.

Removing the LuCI package leaves the daemon, saved configuration, and active
enforcement in place. Removing either optional runtime package preserves
identities, policies, application rules, and temporary-approval state. Removing
the SFO package first evicts supported software-accelerated state before
returning to the core fallback behavior.

After installing the web interface, open:

```text
Network → Client Access
```

1. Review **Clients → Unknown** and create or assign identities.
2. Under **Managed**, choose when the policy applies to each identity.
3. Select the global Internet access policy.
4. Optionally enable application filtering and add identity application rules.
5. When a saved rule currently blocks a target, optionally create a temporary
   approval from the identity or application-rule editor.
6. Review the displayed current result and apply the configuration.

## Current limitations

- Normal-path nftables and application-policy changes are re-evaluated on the
  next scoped packet. With the optional SFO backend, supported accelerated
  flows converge within a verified deadline; hardware and custom acceleration
  remain unsupported.
- Application classification is outbound-only and does not provide full DPI,
  TLS inspection, TCP reconstruction, QUIC parsing/decryption, quota, or
  bandwidth limiting. Return-only traffic is not associated with its outbound
  flow.
- Bandwidth limiting, quota, traffic accounting, private-MAC correlation, and
  unknown-client notifications are not implemented.
- Names and addresses are best-effort discovery information and may be stale or
  incomplete.

## Supported platforms

The application currently targets firewall4/nftables on OpenWrt and
ImmortalWrt. The firewall4 `auto_includes` option must remain enabled.
The optional application backend reserves firewall mark mask `0x60000000`;
custom VPN, QoS, or policy-routing rules must not use those two bits.

The reproducible package baselines are OpenWrt 24.10.8 x86_64 and
ImmortalWrt 24.10.6 x86_64. Automated datapath coverage includes a Linux
bridge, 802.1Q VLAN, IPv4 forwarding, and routed IPv6 forwarding. This does not
claim validation of DSA, PPPoE, big-endian targets, vendor-specific hardware,
or router throughput; those require separate target evidence.

## License

Apache-2.0.
