# net-user-filter

`sandbox-network` installs and verifies persistent Windows Filtering Platform
(WFP) rules that restrict one Windows account to a hostname-filtering proxy on
loopback. It is a host-scoped control for network operations attributed to that
account, not a VM boundary; deployments must separately exclude or test
brokered paths such as BITS, Docker, WSL and Hyper-V.

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

## Proxy adapter contract

The configured adapter must be installed below `Program Files` and implement:

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
