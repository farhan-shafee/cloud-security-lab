# Interview notes

**Why fixtures instead of live AWS?** They make the controls, ground truth, and before/after evidence reproducible without credentials, cost, or deployment risk. They demonstrate engineering behavior, not production AWS experience.

**How does IAM evaluation work?** The parser normalizes a supported subset of identity/trust policies. Static checks inspect Allow statements for wildcard actions/resources, selected IAM mutation permissions, broad role passing, and selected trust patterns. Findings preserve statement evidence.

**What semantics are unsupported?** This is not an effective-permission engine. It does not resolve Deny against Allow, boundaries, SCPs, session/resource policies, live context, or the entire AWS action/resource catalog. Unsupported policy constructs are rejected; supported conditions are structurally parsed but not evaluated. See [controls](controls.md).

**Why deterministic controls instead of a score?** A reviewer can reproduce each condition, inspect its evidence, and challenge its fixed severity. A combined number would conceal assumptions without adding evidence.

**How is remediation verified?** The verifier assesses both source snapshots. It requires the same account/region scope, distinct snapshot IDs, preserved original resource identity/location and bucket sensitivity, and a strictly later timestamp. An original finding becomes VERIFIED_CLOSED only when its resource/control evaluation passes. Persistent and new findings prevent success; later resource configuration is retained as evidence.

**How are detections tested?** Committed event fixtures and separate expected results exercise positives, negatives, malformed input, explicit MFA values, IPv4/IPv6 ingress, timestamps, session/account boundaries, and the correlation window.

**How are false positives handled?** Single-event alerts request review. Only an explicit bounded sequence escalates priority. Neither means malicious. Approved-change context and disposition require human investigation; the lab has no production traffic from which to estimate false-positive rates.

**Why no graph database?** The implemented correlation is a small ordered event join. A graph database would add operational scope without improving that predicate. AegisGraph remains the broader investigation platform.

**Why no live adapter or Terraform?** Both would add collection/deployment assumptions beyond the tested core. The current JSON input already makes the modeled configuration reproducible. A read-only adapter is future work, not a hidden integration.

**What would production require?** Authenticated collection, completeness checks, organization/region discovery, service-specific parsing, explicit permissions, protected log delivery, authorization/change context, alert routing, audited response workflows, retention, and evidence of performance and detection quality under real traffic.

**What would organization-scale AWS add?** Account discovery and delegated collection, organization trails, SCP/boundary context, cross-account trust analysis, data residency/retention rules, ownership mapping, suppression governance, and independently verified evidence. None is claimed here.

**What does a clean result mean?** No modeled condition matched the implemented catalog for that input. It does not mean the account is secure, compliant, or production-ready. Hashes identify input bytes; they do not authenticate their origin.
