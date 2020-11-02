
.PHONY: pylint
pylint: $(GENERATED)
	pre-commit run pylint --all-files

.PHONY: flake8
flake8: $(GENERATED)
	pre-commit run flake8 --all-files

.PHONY: isort
isort:
	pre-commit run isort --all-files

.PHONY: yapf
yapf:
	pre-commit run yapf --all-files

.PHONY: reformat
reformat: isort yapf