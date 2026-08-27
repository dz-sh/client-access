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

## Usage

After installation, open:

```text
Network → Client Access
```

1. Review **Clients → Unknown** and create or assign identities.
2. Under **Managed**, choose when the policy applies to each identity.
3. Select the global Internet access policy.
4. Review the displayed current result and apply the configuration.

## Current limitations

- Policy changes apply to new and related flows. Existing or already offloaded
  flows are not disconnected.
- Bandwidth limiting, quota, traffic accounting, private-MAC correlation, and
  unknown-client notifications are not implemented.
- Names and addresses are best-effort discovery information and may be stale or
  incomplete.

## Compatibility

The application currently targets firewall4/nftables on OpenWrt and
ImmortalWrt. The firewall4 `auto_includes` option must remain enabled.

## License

Apache-2.0.
