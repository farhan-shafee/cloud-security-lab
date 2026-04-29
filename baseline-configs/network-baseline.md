# Network Baseline Configuration

## Baseline Principles
- Restrict inbound access to required ports/sources only.
- Minimize egress and monitor unusual outbound destinations.
- Segment workloads by trust level.

## Baseline Controls
1. No public admin interfaces unless explicitly required.
2. Private subnets for internal workloads where possible.
3. Security-group/network-rule least privilege.
4. Flow/audit logs enabled for security visibility.

## Validation Questions
- Which services are publicly reachable and why?
- Are management ports restricted to approved sources?
- Is there alerting for anomalous network behavior?
