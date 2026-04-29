# Lab Architecture (Text Diagram)

```text
                   +-------------------------------+
                   | Security Operations Layer     |
                   | - Triage Runbook              |
                   | - Findings Reports            |
                   +---------------+---------------+
                                   |
                                   v
+----------------------+   +-------+----------------+   +----------------------+
| Identity Plane       |   | Audit/Detection Plane  |   | Workload Plane       |
| - IAM Users/Roles    |-->| - CloudTrail-style     |<--| - Compute Instance   |
| - Policies           |   |   events               |   | - Object Storage     |
| - Least Privilege    |   | - GuardDuty-style      |   | - App service (mock) |
+----------------------+   |   findings             |   +----------------------+
                           +------------------------+
```

## Trust Boundaries
1. Internet to management console/API.
2. Human identity to cloud account roles.
3. Workload resources to logging/detection services.
4. Security analyst read access to logs/findings.

## Security Design Principles
- Least privilege by default.
- Centralized logging with immutable retention goal.
- Detect, triage, remediate, and revalidate.
