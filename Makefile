PYTHON ?= python
.PHONY: help demo validate test lint format security
help:
	@echo "demo, validate, test, lint, format, security (or use python -m commands)"
demo:
	$(PYTHON) -m cloud_security_lab demo
validate:
	$(PYTHON) scripts/validate_lab.py
test:
	$(PYTHON) -m pytest
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy
format:
	$(PYTHON) -m ruff format .
security:
	$(PYTHON) -m bandit -q -r cloud_security_lab scripts
	$(PYTHON) -m pip_audit -r requirements-dev.lock
