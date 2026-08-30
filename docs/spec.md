# Per-user WFP policy manager

## Objective

`wfp-tool.exe` manages persistent Windows Filtering Platform (WFP) filters for
one Windows account at a time. It implements exact IP-and-port TCP/UDP
allowlists with a lower-priority, SID-scoped default deny. The policy is a
complete configuration file, not a sequence of independently weighted rules.

The intended proxy deployment is:

```text
Sandbox process
    |
    v
WFP per-user allowlist and default deny
    |
    +-- only configured local proxy endpoints
              |
              v
       GOST hostname allowlist
              |
              v
          Internet
```

WFP is host-scoped and attribution-dependent. It is not a VM or network
boundary. Test WSL, Docker, Hyper-V, BITS, brokers, IPv4, IPv6, DNS, UDP/QUIC,
and revocation paths in the deployment that relies on it.

## Configuration

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

The account and `policy_version` are required. `[wfp-allow]` contains one or
more exact endpoint entries:

```text
IPv4: address:port=tcp|udp|tcp,udp
IPv6: [address]:port=tcp|udp|tcp,udp
```

Duplicate endpoint entries and duplicate protocols are errors. IPv4-mapped
IPv6 literals are rejected; an IPv4 entry creates the equivalent mapped IPv6
permit internally.

wfp-tool consumes `[policy] account`, `[policy] policy_version`, and
`[wfp-allow]`. It ignores other sections and keys, allowing GOST and
orchestration to share the file. `proxy_port` and `[allow]` belong to the GOST
helper, which performs hostname filtering. WFP rules here deliberately do not
accept hostnames or wildcard addresses.

## Filter set

For every configured endpoint and selected protocol wfp-tool adds a persistent
`PERMIT` filter scoped with `FWPM_CONDITION_ALE_USER_ID` at:

* `FWPM_LAYER_ALE_AUTH_CONNECT_V4` for IPv4;
* `FWPM_LAYER_ALE_AUTH_CONNECT_V6` for IPv6 and IPv4-mapped IPv6.

It then adds persistent SID-scoped `BLOCK` filters at both connect layers with
no address or protocol condition. This blocks all other attributed TCP and UDP
connections, including direct DNS, DoT, QUIC, SMB, LAN services, and direct
DoH.

Permits use a fixed high filter weight and default denies a fixed lower weight
in one persistent wfp-tool sublayer. The configuration never controls weights.
This is necessary because a permit exception and a catch-all block can only
coexist predictably when their ordering is explicit. Other WFP providers can
still have blocks that win arbitration, so policy compatibility must be tested
on the host.

wfp-tool intentionally does not manage ICMP or ICMPv6. Windows does not
reliably enforce a per-user ICMP policy at the available ALE layers. Complete
per-user ICMP enforcement requires a WFP callout driver or a VM/network
boundary, both of which are out of scope.

## Commands

All commands require an elevated Administrator session.

```text
wfp-tool apply --config <path>
wfp-tool verify --config <path>
wfp-tool remove --config <path>
wfp-tool clear --user <account>
wfp-tool list --user <account>
```

`apply` resolves the account SID, transactionally clears that account's
wfp-tool filters, creates or validates wfp-tool's shared provider and sublayer,
then writes the complete filter set. It verifies the committed policy before
reporting success.

`verify` is read-only. It checks the provider and sublayer metadata and then
requires the owned filters to exactly match every expected filter, including
their provider data, conditions, actions, layers, and explicit weights.

`remove` transactionally deletes the wfp-tool filters belonging to the
configuration's account. It removes the shared wfp-tool provider and sublayer
only when no wfp-tool policy still references them. `clear --user` performs that
same owned-filter cleanup without reading a configuration. `list` accepts an
account rather than a configuration and displays all filters that match that
SID, plus all references to wfp-tool's sublayer so stale fragments are visible.

## Proxy integration

Use `setup-gost.ps1` to create GOST configuration from `[policy] proxy_port`
and `[allow]`. Run the proxy as an identity other than the sandbox account,
bound only to loopback, and treat proxy health checks as a launcher
precondition. `HTTP_PROXY` and `HTTPS_PROXY` configure cooperative clients;
the WFP policy prevents attributed direct TCP/UDP traffic independently.

## Out of scope

* kernel-mode WFP callout drivers;
* transparent TCP or UDP redirection;
* WFP hostname or wildcard-address rules;
* TLS interception, packet inspection, custom DNS, and custom proxy code.

Transparent redirection needs a WFP callout driver. Hostname allowlisting stays
with the proxy, which can resolve changing CDN addresses without changing WFP
filters.

## Operational checks

Before launching a sandboxed session, verify the policy, proxy health, and
loopback binding. Test direct TCP and UDP failures, configured endpoint
success, IPv4, IPv6, DNS, DoT, QUIC, a child process, cleared proxy variables,
and any brokered paths used by the workload. ICMP is deliberately not covered.
