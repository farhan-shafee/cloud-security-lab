# Contributing

Keep the lab reproducible from a clean clone without cloud credentials. Changes should improve executable evidence, security reasoning, or clarity.

- Use synthetic identifiers and documentation IP ranges; no real accounts, credentials, or customer logs.
- Add controls only when the resource model and positive/negative tests support them.
- Keep expected results separate from evaluator logic. Document unsupported semantics and error behavior.
- Preserve deterministic IDs, ordering, and reports. Explain any intentional fixture/output changes.
- Do not add live API calls, paid infrastructure, destructive automation, or unverified AWS-service claims.

## Development

Python 3.11+; the same commands work in PowerShell and Linux shells from the repository root. An isolated virtual environment is recommended. Install development tooling and the package:

```console
python -m pip install -r requirements-dev.lock
python -m pip install -e .
```

Run the checks that exercise a change:

```console
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest
python -m cloud_security_lab validate-fixtures
python scripts/validate_lab.py
python -m cloud_security_lab demo
python -m bandit -q -r cloud_security_lab scripts
python -m pip_audit -r requirements-dev.lock
```

Dependency audit needs network access; assessment, detection, verification, and the demo do not. CI also runs Gitleaks against repository history and the source snapshot. Follow the exact configuration in [.github/workflows](.github/workflows/) and review [VALIDATION.md](docs/VALIDATION.md) for checks actually executed.

`make` and the shell helper are conveniences; Windows does not require WSL. When intentionally refreshing committed evidence, run `python -m cloud_security_lab demo --output-dir reports/generated`, review the diff, and ensure that no local paths or secrets leaked into reports.
