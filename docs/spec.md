# Per-user network restriction for Windows sandbox accounts

## Objective

Restrict direct TCP- and UDP-based network access originating from a dedicated Windows sandbox account, for example `ClaudeSandbox`, so that:

* attributed TCP and UDP operations from every process running as that user are covered
* child processes cannot bypass the restriction
* only explicitly approved TCP and UDP internet destinations are reachable
* hostname changes and CDN IP changes do not require firewall rule updates
* direct TCP, UDP, DNS, QUIC and SMB access is blocked
* the sandbox fails closed when enforcement is unavailable

ICMP is a known exception; see [Known ICMP limitation](#known-icmp-limitation).

The intended path is:

```text
Sandbox process
    |
    v
WFP per-user enforcement
    |
    +-- only local proxy allowed
              |
              v
       hostname allowlist
              |
              v
          Internet
```

## Security model

Assume code running under the sandbox account can:

* execute arbitrary binaries
* launch PowerShell, Git, Node.js, Python, curl and package managers
* modify its own environment variables
* ignore proxy settings
* make direct socket connections
* use TCP, UDP, IPv4 and IPv6
* attempt DNS, DNS-over-TLS, DNS-over-HTTPS and QUIC

Assume it cannot:

* gain administrator privileges
* modify protected WFP objects
* stop or reconfigure privileged services
* inject into privileged processes

Proxy configuration alone is therefore not a security boundary.

## Architecture

Implement two independent components:

### 1. WFP policy installer and verifier

A privileged Windows component installs persistent WFP filters scoped to the sandbox account SID.

The Codex implementation demonstrates the required mechanics:

* persistent provider
* persistent sublayer
* persistent filters
* `FWPM_CONDITION_ALE_USER_ID`
* account matching through an `FWP_SECURITY_DESCRIPTOR_TYPE`
* transactional installation
* stable object GUIDs

A permanent service is optional. A privileged setup helper is enough if filters are persistent and verified before every sandbox launch.

### 2. Local filtering proxy

Use an existing HTTP CONNECT proxy rather than building one initially.

Candidate tools:

* 3proxy
* Squid
* mitmproxy without TLS interception

The proxy must:

* listen only on loopback
* run under a privileged or dedicated service identity
* reject IP-literal destinations
* permit only configured hostnames and ports
* resolve DNS itself
* log accepted and rejected requests
* not expose an unrestricted forwarding interface

TLS interception is not required. HTTPS filtering can be based on the HTTP `CONNECT` hostname.

## Required WFP policy

Apply filters at:

* `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
* `FWPM_LAYER_ALE_AUTH_CONNECT_V6`

Scope every filter using:

```text
FWPM_CONDITION_ALE_USER_ID
```

The account condition should be constructed in the same way as the Codex implementation, using a security descriptor granting `FWP_ACTRL_MATCH_FILTER` to the target account.

Install at least these rules:

### Permit rules

```text
PERMIT sandbox SID -> 127.0.0.1:<proxy-port> TCP
PERMIT sandbox SID -> ::1:<proxy-port> TCP
```

Add only explicitly required local endpoints.

### Block rules

```text
BLOCK sandbox SID -> all other IPv4 outbound
BLOCK sandbox SID -> all other IPv6 outbound
```

The general block is not limited by a TCP or UDP protocol condition.

This implicitly blocks:

* direct TCP
* direct UDP
* DNS on port 53
* DNS-over-TLS on port 853
* QUIC on UDP 443
* SMB
* direct access to LAN services
* DNS-over-HTTPS outside the proxy

### Known ICMP limitation

The account-scoped ALE filters do not reliably block ICMP echo requests on
Windows 11. In testing, `ping.exe` could send IPv4 echo requests while direct
TCP and UDP traffic remained blocked. WFP packet layers that can
unconditionally block ICMP do not expose `FWPM_CONDITION_ALE_USER_ID`, so a
static filter at those layers would block ICMP for the entire host.

A host-wide ICMP block is not acceptable for this design and is deliberately
not installed. Complete per-user ICMP enforcement requires a kernel-mode WFP
callout driver that performs additional attribution, or isolation behind a VM
or network boundary. Blocking `ping.exe` alone is not enforcement because
other programs can generate ICMP traffic.

## Filter ordering

The policy requires both permit and block actions, so ordering must be explicit.

Implement:

* a high-priority permit filter for the loopback proxy
* a lower-priority block filter for all remaining traffic
* deterministic filter weights
* a dedicated persistent sublayer

Do not rely on automatically assigned filter weights.

Test interaction with Windows Defender Firewall and other WFP providers. A block from another provider may override a permit depending on layer and sublayer ordering.

## Proxy configuration

Configure Claude Code with:

```text
HTTP_PROXY=http://127.0.0.1:<proxy-port>
HTTPS_PROXY=http://127.0.0.1:<proxy-port>
```

Do not rely on these variables for enforcement. They only instruct compatible clients how to reach the permitted proxy.

The proxy configuration should use an exact hostname allowlist initially.

Example structure:

```text
allow api.anthropic.com:443
allow required-auth-host.example:443
deny *
```

Do not permit broad wildcard domains until observed traffic proves they are required.

The proxy should resolve destination hostnames dynamically. This avoids maintaining Anthropic IP ranges and handles CDN address changes.

## Installation lifecycle

The installer must:

1. Run elevated.
2. Resolve the configured sandbox account.
3. Open the WFP engine.
4. Begin a transaction.
5. Create or verify the persistent provider.
6. Create or verify the persistent sublayer.
7. Remove previous filters by stable GUID.
8. Add current permit and block filters.
9. Commit the transaction.
10. Verify that every expected filter exists.
11. Return failure if installation or verification fails.

Use stable GUIDs. Regenerating them would leave orphaned WFP objects, as noted in the Codex implementation.

Unlike Codex, failure must be fatal for sandbox startup. Codex logs WFP setup failures and continues; that is unsuitable for a strict sandbox.

## Launch sequence

Before starting a sandbox session:

1. Verify the sandbox account exists.
2. Verify the local proxy is running.
3. Verify the proxy is bound only to loopback.
4. Verify all required WFP filters exist.
5. Optionally test that direct internet access fails.
6. Test that an approved proxy request succeeds.
7. Only then launch Claude Code under the sandbox account.

If any check fails, do not launch the agent.

## Logging requirements

Record:

* filter installation and verification results
* target account SID
* active policy version
* proxy startup and shutdown
* approved hostname connections
* rejected hostname requests
* direct connection attempts, where practical
* configuration changes

Logs must be stored outside directories writable by the sandbox user.

## Configuration

Use a protected configuration file containing:

```text
sandbox account
proxy listen address
proxy port
approved hostnames
approved destination ports
policy version
logging path
```

Only administrators should be able to modify it.

## Initial implementation path

### Phase 1: WFP enforcement prototype

Adapt the Codex WFP implementation.

Replace the existing narrow `FilterSpec` definitions with:

* loopback proxy permit v4
* loopback proxy permit v6
* general outbound block v4
* general outbound block v6

Add condition support for:

* remote address
* remote port
* protocol where needed

Add support for `FWP_ACTION_PERMIT`.

### Phase 2: Existing proxy integration

Run 3proxy, Squid or mitmproxy locally.

Configure exact hostname allowlists and `CONNECT` restrictions.

Validate Claude Code authentication and API traffic.

### Phase 3: Verification and hardening

Test:

* curl direct to IP
* curl direct to hostname
* UDP socket
* QUIC
* DNS port 53
* DNS-over-TLS
* IPv6
* PowerShell web requests
* Git
* Node.js HTTPS
* Python requests
* child processes
* `NO_PROXY=*`
* cleared proxy variables
* local LAN access

All listed direct TCP and UDP paths must fail. Approved proxy traffic must succeed.

### Phase 4: Operational integration

Integrate policy verification into the launcher.

Add installation, repair and uninstall commands.

Possible interface:

```text
sandbox-network install
sandbox-network verify
sandbox-network repair
sandbox-network remove
sandbox-network test
```

## Out of scope for the first version

Do not initially implement:

* a kernel-mode WFP callout driver
* transparent connection redirection
* TLS interception
* packet inspection
* custom DNS server
* custom proxy implementation
* dynamic traffic learning
* automatic wildcard generation

These add substantial complexity. A kernel-mode callout is required only if
the security objective expands to reliable per-user ICMP enforcement.

## Acceptance criteria

The implementation is complete when:

* attributed TCP and UDP traffic from every process under the sandbox SID is restricted
* arbitrary direct TCP and UDP connections fail
* IPv4 and IPv6 are both covered
* direct DNS and encrypted DNS bypasses fail
* only the local proxy is reachable over TCP and UDP
* the proxy allows only approved hostnames
* hostname IP changes require no WFP update
* proxy failure prevents TCP- and UDP-based internet access
* WFP setup failure prevents sandbox startup
* the sandbox user cannot alter the policy
* uninstall cleanly removes all owned WFP objects
* the per-user ICMP limitation is accepted or enforcement is moved to a VM/network boundary

## Recommended final design

```text
Elevated setup helper
    -> installs persistent per-SID WFP filters

Sandbox launcher
    -> verifies WFP policy and proxy health
    -> launches Claude Code only when enforcement is active

Existing local proxy
    -> performs hostname allowlisting
    -> resolves changing destination addresses

WFP
    -> prevents attributed direct TCP and UDP proxy bypasses
```
