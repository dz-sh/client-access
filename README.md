# luci-app-client-access

An OpenWrt/ImmortalWrt LuCI application for discovering LAN clients and
controlling their Internet access with firewall4/nftables.

## Features

- Discover LAN clients with best-effort names and IP addresses.
- Create stable identities for the clients you want to manage.
- Associate multiple MAC addresses with one identity.
- Choose a global blacklist or whitelist policy.
- Keep access control globally disabled until you are ready to enable it.
- Activate an identity permanently or only during weekly time periods.
- Use one or more periods per day, different periods on different weekdays, and
  periods that cross midnight.
- Control IPv4 and IPv6 forwarding without creating one nftables rule per
  client.

## Global modes

Access control is disabled by default.

| Mode | Unmanaged and inactive clients | Active identities |
| --- | --- | --- |
| Blacklist | Allowed | Blocked |
| Whitelist | Blocked | Allowed |

Changing the global mode reverses the meaning of every active identity.

## Identities and unknown clients

The application separates discovered clients from identities:

- **Unknown Clients** are temporary observations which have not been assigned
  to an identity. They follow the global default policy and are not scheduled.
- **Managed Identities** are clients you have explicitly created and named.
  Their MAC bindings and activation periods are persistent.

From **Unknown Clients**, you can either create a new identity or bind the
observed MAC to an existing identity. Private MAC addresses are never merged
automatically.

An identity can be:

- **Inactive** — follow the global default policy.
- **Always active** — always use the active-identity behavior for the selected
  global mode.
- **Active during schedule** — use active-identity behavior only while a weekly
  period matches.

## Weekly schedules

Schedule entries use:

```text
DAYS@HH:MM-HH:MM
```

Examples:

```text
*@08:00-21:00
mon,tue,wed,thu,fri@08:00-21:30
sat,sun@09:00-23:00
mon@08:00-12:00
mon@14:00-20:00
fri,sat@22:00-07:00
```

- `*` means every day; otherwise use `mon` through `sun`.
- Add multiple entries to combine several periods.
- A period crossing midnight ends on the following day.
- Times use the router's local timezone with one-minute resolution.

## Usage

After installation, open:

```text
Network → Client Access
```

1. Review **Unknown Clients** and create or assign identities.
2. Configure identity activation under **Identities & Policy**.
3. Select blacklist or whitelist mode.
4. Review the displayed mode-dependent behavior.
5. Enable global enforcement and apply the configuration.

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
