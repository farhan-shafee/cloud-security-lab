# Network review baseline

The executable scope is security-group ingress configuration:

- `NET-001`: world-open IPv4/IPv6 ingress permits TCP 22 or 3389, including all-protocol rules.
- `NET-002`: world-open ingress permits all protocols.

Both inspect explicit `/0` CIDRs. A `/0` all-protocol rule intentionally produces both findings: administrative exposure and unrestricted protocol exposure are separate conditions. Exact predicates and limitations are in the [control catalog](../docs/controls.md).

The remediated fixture replaces world access with a synthetic approved source range. The lab does not scan hosts, evaluate routes/NACLs, model multiple attached security groups, analyze egress, or verify Flow Logs. Public reachability cannot be proven from this snapshot alone. Database ports, broad non-`/0` CIDRs, and source security-group references are outside the selected checks.
