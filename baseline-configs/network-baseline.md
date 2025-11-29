# Network baseline

Identity gets most of the attention in this lab, but network exposure is the
other half of the blast-radius question: even a well-scoped role doesn't help if
the admin interface is on the public internet.

## Principles

- **Inbound is closed until it has a reason to be open.** Required ports, from
  required sources, and nothing else.
- **Egress is monitored, not ignored.** Exfiltration and C2 leave by the same
  door as legitimate traffic; unusual outbound destinations are worth an alert.
- **Segment by trust level.** A compromised public-facing service shouldn't have
  a flat path to the data tier.

## Controls the lab checks for

1. No public admin interfaces (SSH, RDP, database ports) unless explicitly
   justified and time-boxed.
2. Internal workloads in private subnets, reachable only through a controlled
   ingress point.
3. Security-group / NACL rules written least-privilege, the same as IAM.
4. Flow logs enabled, so "who talked to whom" is answerable after the fact.

## Questions to ask

- Which services are reachable from the internet, and does each one need to be?
- Are management ports (22, 3389, 5432, ...) restricted to an approved source
  range or a bastion?
- Is there alerting on anomalous outbound traffic, or only inbound?
