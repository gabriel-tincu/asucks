
clean:
	rm -rf rpm/ dist/ build/


.PHONY: pylint
pylint:
	pre-commit run pylint --all-files

.PHONY: flake8
flake8:
	pre-commit run flake8 --all-files

.PHONY: copyright
copyright:
	grep -EL "Copyright \(c\) 20.* Aiven" $(shell git ls-files "*.py" | grep -v __init__.py)

.PHONY: unittest
unittest:
	python3 -m pytest -s -vvv tests/

.PHONY: test
test: copyright lint unittest

.PHONY: isort
isort:
	pre-commit run isort --all-files

.PHONY: yapf
yapf:
	pre-commit run yapf --all-files

.PHONY: reformat
reformat: isort yapf

.PHONY: pre-commit
pre-commit: $(GENERATED)
	pre-commit run --all-files

.PHONY: lint
lint: pre-commit


.PHONY: rpm
rpm:
	python setup.py bdist_rpm
	rm -rf build/
