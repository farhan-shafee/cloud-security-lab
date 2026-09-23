# Threat model

Two systems are in scope: the synthetic AWS-style environment and the local code/CI evaluating its fixtures. No live account is assessed. See [architecture](architecture.md).

## Modeled cloud threats

| Threat | Observable evidence | Response and limit |
|---|---|---|
| Overprivileged identities | Broad Allow actions/resources, IAM mutations, role passing | Static findings inspect selected patterns; no effective-permission calculation. |
| Unsafe trust | Broad principals and unconditioned external account/root trust | Trust-document checks; no organization graph or full condition evaluation. |
| Credential misuse | Root API use, IAM-user login explicitly reporting no MFA, access-key creation | Review alerts preserve evidence. Authorization and compromise need human context. |
| Public exposure | Missing bucket guardrails and world-open security-group rules | Fixture configuration checks; no reachability scan or full bucket-policy evaluation. |
| Encryption policy gap | Sensitive bucket not meeting customer-managed SSE-KMS requirement | Configuration intent only; no ciphertext or key-policy verification. |
| Logging disablement | Trail configuration gaps or successful StopLogging/DeleteTrail | Findings and alerts; configuration does not prove delivery or retention. |
| Security-control modification | Policy-version change followed by logging disablement | Explicit bounded correlation raises investigation priority, not a malicious verdict. |

The lab does not infer an attack path merely because multiple findings exist. Correlation requires documented account, principal/session, ordering, and time-window predicates.

## Lab trust boundaries

| Boundary / failure | Mitigation | Residual risk |
|---|---|---|
| Fixture author → parser | Versioned contracts, type/duplicate checks, malformed-input tests | Valid but fabricated or incomplete data remains possible. |
| Parser → evaluator | Explicit supported fields and IAM constructs; reject unsupported semantics | Many valid AWS configurations remain unsupported. |
| Repository → ground truth | Expected results separate from evaluator; positive/negative/boundary tests | A contributor can alter both code and answers; review remains necessary. |
| Assessment → closure | Re-assessment of later compatible snapshots; unresolved/new findings retained | No proof of deployment, persistence, or unmodeled risk removal. |
| Source bytes → report | Source hashes, stable IDs, deterministic output | Hashes are not signatures or trusted timestamps. |
| Events → triage | Source IDs, actor, timestamp, evidence, bounded correlation | Missing events, clock issues, or other attack sequences can evade detection. |
| Dependencies / CI → result | Minimal runtime, constrained tooling, tests, repository security gates | Compromised tooling/Actions could falsify evidence; workflow changes need review. |

## False positives and false negatives

Authorized policy changes and key creation can produce review alerts. There is no ticket system, geolocation baseline, behavioral model, or business authorization context. Console MFA detection requires an explicit `No` for an IAM user; absent data and federated logins do not prove missing MFA.

IAM findings can persist despite a restrictive Deny, boundary, SCP, or condition because their combined effect is not evaluated. An unflagged policy can contain dangerous combinations outside the catalog. See [controls](controls.md) for unsupported semantics.

## Secrets and scope

Use invented account/principal IDs and reserved documentation IPs. Do not commit credentials, customer logs, real snapshots, or private identifiers. Required flows need no AWS credentials. Follow [SECURITY.md](../SECURITY.md) if sensitive data is discovered.

Out of scope: application exploitation, live containment, organization-wide authorization analysis, cloud deployment, cryptographic CloudTrail verification, or integrations with Security Hub, GuardDuty, Config, Inspector, and IAM Access Analyzer.
