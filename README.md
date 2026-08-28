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

V4.1 is best effort: it allows packets in a small initial window while
classifying one early packet of a new flow, uses DNS/IP/port metadata rather
than full DPI, and treats ambiguous or
encrypted traffic as unclassified. LuCI reports classification coverage and
resource shedding. Software and hardware flow offloading must be disabled
while this layer is enabled.

## Usage

After installation, open:

```text
Network → Client Access
```

1. Review **Clients → Unknown** and create or assign identities.
2. Under **Managed**, choose when the policy applies to each identity.
3. Select the global Internet access policy.
4. Optionally enable application filtering and add identity application rules.
5. Review the displayed current result and apply the configuration.

## Current limitations

- The nftables workflow does not disconnect existing conntrack or offloaded
  flows. Application-policy changes are re-evaluated on the next software-path
  packet of a cached flow.
- Application classification is outbound-only and does not provide full DPI,
  TLS interception, QUIC decryption, quota, or bandwidth limiting.
- Bandwidth limiting, quota, traffic accounting, private-MAC correlation, and
  unknown-client notifications are not implemented.
- Names and addresses are best-effort discovery information and may be stale or
  incomplete.

## Compatibility

The application currently targets firewall4/nftables on OpenWrt and
ImmortalWrt. The firewall4 `auto_includes` option must remain enabled.
The optional application backend reserves firewall mark mask `0x60000000`;
custom VPN, QoS, or policy-routing rules must not use those two bits.

## License

Apache-2.0.
