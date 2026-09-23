# Security policy

This is an offline synthetic-data lab with no production service. Its relevant security concerns include committed secrets, unsafe input handling, incorrect security conclusions, and compromised development or CI tooling.

## Reporting

Report suspected live credentials or private data through GitHub private vulnerability reporting if enabled, or contact the maintainer privately. Do not post credentials in public issues. Ordinary correctness bugs and reproducible false positives can be reported publicly with synthetic inputs.

If a real credential is exposed, revoke/rotate it first and follow the owner's incident procedure before cleaning history. Deleting a file does not revoke a credential.

## Data and execution

- Required commands need no AWS account, SDK, credentials, or paid resources.
- Use invented identifiers and documentation address ranges. Never commit real account snapshots, customer logs, or credentials.
- Fixture files are untrusted input; rejection must produce an explicit error, not a clean assessment.
- Generated hashes identify input bytes; they do not authenticate AWS evidence.
- Review changes to predicates, fixtures, expected results, dependencies, and Actions together.

See the [threat model](docs/threat-model.md) and [validation record](docs/VALIDATION.md) for coverage and executed security checks. Reported findings are static lab observations, not complete AWS authorization decisions or incident verdicts.
