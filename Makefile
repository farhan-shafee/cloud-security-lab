.PHONY: validate lint tree help

help:
	@echo "make validate  - structure, JSON, and linter self-test checks"
	@echo "make lint       - run the IAM linter over every example policy"
	@echo "make tree       - list tracked files"

validate:
	./scripts/validate_lab.sh

lint:
	@python3 scripts/analyze_policy.py examples/iam/*.json || true

tree:
	@git ls-files 2>/dev/null || find . -type f -not -path './.git/*'
