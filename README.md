# net-user-filter

`sandbox-network` installs and verifies persistent Windows Filtering Platform
(WFP) rules that restrict one Windows account to a hostname-filtering proxy on
loopback. It is a host-scoped control for network operations attributed to that
account, not a VM boundary; deployments must separately exclude or test
brokered paths such as BITS, Docker, WSL and Hyper-V.

## Known limitation: ICMP

The policy does not reliably block ICMP per user. On Windows 11, ICMP echo
requests made by `ping.exe` can bypass the account-scoped filters even while
direct TCP and UDP are blocked. WFP layers that can unconditionally block ICMP
do not provide the user identity needed to limit that block to the sandbox
account, so this tool deliberately does not install a host-wide ICMP block.

Treat this as enforcement for attributed TCP and UDP traffic, not complete
per-user network isolation. Strict ICMP isolation requires a kernel-mode WFP
callout driver or a VM/network boundary. The `test` command does not claim to
test ICMP enforcement.

## Build

Requirements: the latest Visual Studio C++ toolchain, Windows SDK, CMake,
Ninja, and PowerShell.

```powershell
.\build.ps1
```

The script configures, builds, and runs CTest. Pass
`-Configuration Debug` when needed.

## Commands

```text
sandbox-network install --config <path>
sandbox-network verify
sandbox-network repair [--config <path>]
sandbox-network remove
sandbox-network test
```

`install`, `repair`, and `remove` require elevation. `verify` is read-only and
must return success immediately before a sandbox launcher starts the target
process. `test` must run as the configured sandbox account.

Exit codes are `0` for success, `2` for usage/configuration errors, `3` for
elevation or identity preconditions, `4` for WFP failures, `5` for proxy
failures, and `6` for verification/test failures.

Configuration is installed at
`%ProgramData%\SandboxNetwork\policy.ini`; see `policy.example.ini`. Proxy
addresses are deliberately fixed to `127.0.0.1` and `::1`.

Set `policy.audit_blocked=true` to enable system-wide failure auditing for
blocked WFP connections. The default is `false`. Apply a change with
`repair --config <path>`. This diagnostic setting can produce events for other
accounts too. Setting it to `false`, or removing the policy, disables failure
auditing for this system subcategory while preserving success auditing.

Blocked connections are written to the Windows Security log as event 5157.
From an elevated shell, show the latest 100 events caused specifically by this
policy's IPv4 and IPv6 block filters with:

```text
sandbox-network logs
```

## Proxy adapter contract

The configured adapter must be installed below `Program Files` or `ProgramData`
and implement:

```text
adapter.exe apply  --policy <installed-policy>
adapter.exe verify --policy <installed-policy>
adapter.exe remove --policy <installed-policy>
```

The adapter must return zero only when the proxy is loopback-only, runs as an
identity other than the sandbox account, applies the exact hostname/port
allowlist, rejects IP-literal destinations, resolves DNS itself, and writes
protected accept/reject logs.

Policy command results are written to the protected Windows Application event
log with source `SandboxNetwork`. When enabled by the administrator, direct
connection auditing uses the standard Windows Filtering Platform audit policy
and events 5156/5157.

The sandbox launcher should set:

```text
HTTP_PROXY=http://127.0.0.1:<proxy-port>
HTTPS_PROXY=http://127.0.0.1:<proxy-port>
```

Those variables are cooperative client configuration. The WFP policy is what
prevents direct socket bypass.

## Dummy adapter for enforcement testing

`dummy-proxy-adapter.exe` is built alongside the policy tool. It is deliberately
not a forwarding proxy: it binds `127.0.0.1` and `::1`, returns `200` for an
allowlisted `CONNECT`, returns `403` for everything else, and then closes the
connection. This is enough to test the WFP permit and default-deny rules.

From an elevated PowerShell session:

```powershell
$toolDirectory = Join-Path $env:ProgramFiles 'SandboxNetwork'
$adapterDirectory = Join-Path $env:ProgramData 'SandboxNetwork'
New-Item -ItemType Directory -Force -Path $toolDirectory
New-Item -ItemType Directory -Force -Path $adapterDirectory
Copy-Item .\out\build\sandbox-network.exe $toolDirectory
Copy-Item .\out\build\dummy-proxy-adapter.exe $adapterDirectory

& "$toolDirectory\sandbox-network.exe" install --config .\policy.example.ini
& "$toolDirectory\sandbox-network.exe" verify
```

Keep `sandbox-network.exe` and `dummy-proxy-adapter.exe` from the same build.
When upgrading a running dummy adapter, stop it before replacing both binaries.

Set `policy.account` to the local test account before installing. Then run the
installed `sandbox-network.exe test` as that account. It checks the permitted
proxy path, blocked direct TCP and UDP over IPv4 and IPv6, and repeats the
bypass checks in a child process.

Remove the test policy from an elevated session:

```powershell
& "$toolDirectory\sandbox-network.exe" remove
```

Do not use the dummy adapter for real traffic; it never forwards CONNECT data.
