.PHONY: validate show-tree

validate:
	./scripts/validate_lab.sh

show-tree:
	rg --files
