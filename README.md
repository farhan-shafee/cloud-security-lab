# cloud-security-lab

Notes and examples from working through cloud security fundamentals -- IAM,
logging, and audit-event triage -- using AWS-style sample data. There's no live
account behind it; everything runs locally.

This is a learning project. The aim is reps on the work a junior cloud security
or SOC analyst actually does: reading policies, looking at sign-in and API
events, and writing up what's wrong.

## Layout so far

- `baseline-configs/` -- IAM and network hardening baselines
- `examples/iam/` -- over-privileged vs. least-privilege policy examples
- `examples/` -- logging notes and sample events

Still to come: a threat model, detection content, and a triage runbook.

## Requirements

- bash and python3
