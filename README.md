# luci-app-client-access

`luci-app-client-access` is an OpenWrt/ImmortalWrt LuCI application for discovering known LAN clients and controlling whether each client may create new Internet-bound flows.

## Version 1 scope

- IPv4 and IPv6 forwarding through firewall4/nftables.
- A global blacklist mode (allow by default) or whitelist mode (deny by default).
- A separate global master switch which is off by default and bypasses both modes.
- Per-device `inherit`, `always_allow`, `always_block`, `allow_during`, and `block_during` policies.
- Multiple MAC addresses and multiple weekly schedule windows per logical device.
- Best-effort names and addresses from LuCI host hints, which aggregate DHCP, neighbour, static-host, and related data.
- One global scheduler and one runtime MAC exception set, regardless of the number of devices.

Version 1 deliberately does not implement bandwidth limiting, traffic accounting, unknown-device notifications, or immediate disconnection of existing sessions.

## Flow semantics

The forward hook evaluates only conntrack `new` and `related` tuples. Existing and already offloaded flows are intentionally not removed or re-evaluated when a policy changes. A newly denied client can therefore retain an existing session until that conntrack entry expires.

This boundary keeps the steady-state forwarding cost small and avoids flushing unrelated conntrack state. Immediate disconnect can be added later as an explicit, separate operation.

When the global master switch is off, all runtime match, exception, and mode sets are emptied. The daemon remains available for device discovery and configuration, but no forwarding policy is enforced. The shipped UCI configuration sets this switch to off.

## Policy model

| Global mode | Default verdict | MAC exception set contains |
| --- | --- | --- |
| `blacklist` | allow | clients currently denied |
| `whitelist` | deny | clients currently allowed |

Every enabled, non-inherited client policy is evaluated in userspace. Conflicting policies for the same MAC use deny-wins behavior. Disabled and inherited entries do not participate in conflict resolution.

Scheduled policies fail closed for their affected clients when the system clock is earlier than 2020 or when a schedule is invalid. If firewall zones cannot be resolved, enforcement is globally deactivated by using empty interface sets and the runtime status reports the error; this avoids accidentally blocking every forwarded packet because of an interface configuration problem.

## Schedule syntax

Each schedule entry has this form:

```text
DAYS@HH:MM-HH:MM
```

Examples:

```text
mon,tue,wed,thu,fri@08:00-21:30
sat,sun@09:00-23:00
*@23:00-07:00
```

- Days use `mon` through `sun`; `*` means every day.
- Multiple entries are combined as a union.
- Crossing midnight is supported.
- Equal start and end times mean the whole selected day.
- The router's local timezone is used.

## Runtime architecture

`client-accessd` owns the runtime state:

1. Read UCI as the source of truth.
2. Evaluate every client against the current wall clock.
3. Calculate the earliest transition across all schedules.
4. Materialize the current exception MACs, source interfaces, destination interfaces, and mode into named nftables sets using one atomic nft transaction.
5. Arm one uloop timer using monotonic elapsed time.

The timer wakes at the earlier of the next schedule transition or the configured safety interval. The default 60-second safety wakeup also performs a full reconcile, which repairs runtime set contents after an out-of-band firewall4 reload and handles manual wall-clock changes. NTP and interface hotplug events request an immediate reconcile.

The packet path is fixed-size: an interface match and jump, a mode-set lookup, and one MAC-set lookup for new or related tuples. No per-client nft rule is created, and there is no per-packet logging.

## UCI example

```uci
config client_access 'main'
	option enabled '1'
	option mode 'blacklist'
	option deny_action 'reject'
	list source_zone 'lan'
	list destination_zone 'wan'
	option safety_interval '60'

config device
	option name 'Tablet'
	option enabled '1'
	list mac '02:00:00:00:00:01'
	option policy 'allow_during'
	list schedule 'mon,tue,wed,thu,fri@08:00-21:30'
```

## Remote build and validation

All repository build and validation jobs run in GitHub-hosted Linux environments. The workflow contains:

- JSON, shell, LuCI JavaScript, and nftables syntax checks.
- Policy unit tests using an official ucode checkout built on the remote runner.
- An OpenWrt SDK package build using `openwrt/gh-action-sdk`.
- An ImmortalWrt SDK package build using `immortalwrt/gh-action-sdk`.
- Package and build-log artifacts retained for inspection.

The SDK jobs currently use the rolling `x86_64` SDK as a portability baseline. Release-specific and hardware-target matrices can be added once the supported release floor and target devices are fixed.

SDK compilation proves package construction and dependency compatibility. End-to-end validation of ubus, procd, firewall reload behavior, and forwarding still requires an isolated x86_64 router VM or an explicitly authorized target gateway.

## Installation notes

Installing the package enables `client-accessd`, reloads firewall4 so its automatic nftables includes are present, and restarts rpcd so the LuCI menu and ACLs are visible. Enforcement remains disabled until enabled in **Network → Client Access → Policies**.

The firewall4 option `auto_includes` must remain enabled because the application installs fragments under `/usr/share/nftables.d/`.

## License

Apache-2.0.
