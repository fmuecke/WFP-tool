# user-net-lock loopback policy

## Contract

For a supplied local account and proxy port, `user-net-lock` owns exactly one
SID-scoped outbound policy. Its permit rules are fixed to loopback TCP on that
port; its remaining rules block attributed TCP and UDP. The program never
accepts addresses, protocol choices, hostnames, or policy files.

```text
user-net-lock apply  --user AgentSandbox --port 8080
user-net-lock verify --user AgentSandbox --port 8080
user-net-lock remove --user AgentSandbox
user-net-lock list   --user AgentSandbox
```

`apply` first validates the shared provider and sublayer, restoring their
administrative DACLs and managed-account read ACEs when necessary. It then transactionally removes this tool's prior policy
for the account, creates the provider, sublayer, and seven fixed filters as
needed, commits, then verifies the result. A shared object whose persistence,
provider association, or effective weight is below the policy baseline fails
before any filter is changed. `remove` removes only those filters. The shared provider
and sublayer are deleted only after no filter refers to them.

## Fixed filters

At `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, the
tool installs three high-weight permits for TCP to `127.0.0.1`, `::1`, and
`::ffff:127.0.0.1` on the requested port. It installs four lower-weight block
filters: TCP and UDP at each connect layer. ICMP and ICMPv6 are out of scope.

Each filter is constrained with `FWPM_CONDITION_ALE_USER_ID` for the target
SID. Windows represents that condition as a security descriptor, so the tool
creates and verifies that descriptor solely to bind the filter to the selected
account. Separately, it creates and verifies the provider, sublayer, and each
filter with a protected DACL granting full control only to `SYSTEM` and
built-in Administrators. Each managed account receives read-only WFP access
(including `READ_CONTROL`) to the shared objects and its own filters, so it
may `list` and `verify` its own policy. The filter container grants it only the
enumeration right needed to list its readable filters. It receives no write,
delete, ownership, or DACL-change right. It does not inspect directory or
configuration-file ACLs.

## Boundaries

The proxy configurator is responsible for the hostname-and-port allowlist,
GOST acquisition and verification, loopback-only binding, service lifecycle,
and proxy health. `agent-win-sandbox` orchestrates the proxy first and calls
`apply` only after the listener is ready.

This remains a host-scoped, attribution-dependent control. Validate all
brokered and virtualized networking paths in the actual deployment.

`apply` and `remove` always require elevation. A non-elevated caller of
`verify` or `list` must be the target account; administrators may inspect any
account. This identity check narrows the CLI surface, while the WFP ACLs remain
the enforcement boundary for direct WFP API callers.
