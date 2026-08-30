# net-user-filter

`wfptool.exe` is the sole WFP policy manager. It applies an elevated,
persistent, per-user outbound allowlist: exact TCP/UDP endpoints are permitted
at a fixed high weight, then lower-weight default-deny filters block every
other attributed IPv4 and IPv6 TCP/UDP connection.

This is a host-scoped control for traffic attributed to the account, not a VM
boundary. Validate brokered paths such as BITS, Docker, WSL, and Hyper-V in the
deployment that relies on it.

## Build

```powershell
.\build.ps1
```

The script builds Release and runs CTest. Use `-Configuration Debug` for Debug.

## Policy

```ini
[policy]
account=ClaudeSandbox
policy_version=1
proxy_port=8080

[wfp-allow]
127.0.0.1:8080=tcp
[::1]:8080=tcp

[allow]
api.anthropic.com=443
```

`[wfp-allow]` is wfptool's exact-IP policy: `address:port` for IPv4 and
`[address]:port` for IPv6. Values are `tcp`, `udp`, or `tcp,udp`. An IPv4
permit also covers its IPv4-mapped IPv6 form. wfptool reads `account`,
`policy_version`, and `[wfp-allow]`; it leaves `[allow]` and other GOST or
orchestration sections alone. At least one WFP endpoint is required.

`proxy_port` and `[allow]` remain for `setup-gost.ps1`, which generates GOST's
hostname allowlist. WFP itself cannot safely implement hostname or wildcard
rules here; it only accepts exact address literals.

## Commands

```text
wfptool apply --config <path>
wfptool verify --config <path>
wfptool remove --config <path>
wfptool clear --user <account>
wfptool list --user <account>
```

All commands require an elevated Administrator session.

- `apply` atomically clears that account's wfptool filters, replaces them with
  the complete configuration, then verifies the result.
- `verify` is read-only and requires the provider, sublayer, and every expected
  filter to match exactly.
- `remove` removes that account's wfptool filters. It removes the shared
  provider and sublayer only when no wfptool policy still references them.
- `clear` performs the same cleanup without reading a configuration file. It
  only clears filters owned by wfptool for that SID.
- `list` prints every filter that matches the account plus any filter that
  references wfptool's sublayer, including action, endpoint, layer, provider,
  and filter key. The latter exposes stale references that prevent recovery.

```powershell
.\out\build\wfptool.exe apply --config .\policy.example.ini
.\out\build\wfptool.exe verify --config .\policy.example.ini
.\out\build\wfptool.exe list --user ClaudeSandbox
```

wfptool reserves its own provider and sublayer. `apply` clears the selected
account's wfptool filters before installing the new policy.

## ICMP and limits

wfptool intentionally does not manage ICMP or ICMPv6. Windows does not
reliably enforce per-user ICMP filters at the available ALE layers; complete
per-user ICMP enforcement needs a WFP callout driver or a VM/network boundary.
Transparent redirects, hostname or wildcard WFP filters, and kernel drivers
are out of scope.

## GOST helper

`setup-gost.ps1` generates `%ProgramData%\SandboxNetwork\gost\gost.yml` from
`proxy_port` and `[allow]`, with loopback listeners and a hostname-and-port
allowlist. It validates the generated configuration but does not install or
start a service. Run GOST under an identity other than the sandbox account.

GOST's bypass ACL does not distinguish `CONNECT` from ordinary HTTP: allowing
`hostname:80` also permits `CONNECT` to that destination.
