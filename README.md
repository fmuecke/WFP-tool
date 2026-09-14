# wfp-tool

`wfp-tool.exe` is the small, elevated enforcement primitive for Agent Sandbox.
For one Windows account and one loopback proxy port, it creates, verifies, or
removes a persistent WFP policy:

- permits TCP only to `127.0.0.1:<port>`, `[::1]:<port>`, and the IPv4-mapped
  IPv6 form of the same loopback endpoint;
- blocks all other outbound TCP and UDP attributed to that account;
- leaves ICMP and ICMPv6 unmanaged.

It does not read configuration files, install a proxy, download software,
resolve hostnames, or interpret an allowlist. It protects its WFP provider,
sublayer, and filters with the fixed `SYSTEM`/Administrators DACL and verifies
that DACL. The proxy configurator owns the remaining concerns;
`agent-win-sandbox` calls this tool only after the loopback proxy is running
and healthy.

## Commands

All commands require an elevated Administrator session.

```text
wfp-tool apply --user <account> --port <port>
wfp-tool verify --user <account> --port <port>
wfp-tool remove --user <account>
wfp-tool list --user <account>
```

`apply` replaces only this tool's existing filters for the selected account,
installs the fixed loopback policy, and verifies it before reporting success.
`remove` deletes only this tool's filters for the selected account. `list`
prints those filters, including any stale loopback policy from a different
port.

The WFP `ALE_USER_ID` condition necessarily contains a security descriptor for
the selected account SID; that is the Windows API representation of a
per-user filter, not a configurable ACL feature.

WFP attribution is host-scoped, not a VM or network boundary. Test WSL,
containers, virtual machines, BITS, and other brokered paths in the deployment
that relies on it.

## Build

```powershell
.\build.ps1
```

The script builds Release and runs CTest. Use `-Configuration Debug` for a
Debug build.

### Elevated integration test in Windows Sandbox

The default test run is non-mutating. To exercise real WFP DACL tampering,
use the Windows Sandbox CLI runner. It refuses to attach to an existing
sandbox, starts a fresh unconfigured guest, shares one writable directory,
copies the test executable there, runs it as `SYSTEM`, validates `result.txt`,
and stops the guest:

```powershell
.\tests\Invoke-WfpIntegrationInWindowsSandbox.ps1
```

The test applies and verifies the policy, confirms exactly seven filters, then
removes it and confirms its filters, provider, and sublayer are gone. It also
weakens the provider, sublayer, and filter DACLs, requires `verify` to fail for
each case, and reapplies to prove DACL repair. Finally, it proves repeated
apply replaces a user's prior port policy and that removing one user's policy
leaves the other's intact. The WFP changes and test accounts exist only in the
Windows Sandbox guest; no host wfp-tool policy is modified.

The same runner also launches a real traffic-enforcement test as the two
disposable accounts. It proves the target account can use the configured IPv4
and IPv6 loopback TCP proxy port, cannot use a different loopback port or TCP
and UDP to a non-loopback address, and that the second account can still reach
the non-loopback TCP and UDP listeners.
