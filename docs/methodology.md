# Cloud Security Lab Methodology

## Objective
Evaluate a sample cloud environment for common security weaknesses and produce actionable remediation artifacts suitable for portfolio demonstration.

## Method
1. **Asset & trust-boundary identification**
2. **Threat modeling (STRIDE-inspired)**
3. **Control review** (IAM, logging, network, detection)
4. **Event triage exercises**
5. **Findings documentation** (severity, impact, recommendation)
6. **Remediation verification**

## Analysis Framework
- Likelihood: Low / Medium / High
- Impact: Low / Medium / High
- Severity: Informational / Low / Medium / High

## Evidence Standards
- Every finding should include:
  - Observation
  - Why it matters
  - Evidence (event or policy snippet)
  - Recommended fix
  - Validation step

## Role Alignment
- SOC Analyst: triage flow, event interpretation, escalation notes.
- Security Analyst: findings quality, risk articulation, report output.
- Cloud Security Engineer: IAM hardening logic, control coverage, repeatable validation.
