
clean:
	rm -rf rpm/ dist/ build/


.PHONY: pylint
pylint:
	pre-commit run pylint --all-files

.PHONY: flake8
flake8:
	pre-commit run flake8 --all-files


.PHONY: unittest
unittest:
	python3 -m pytest -s -vvv tests/

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

.PHONY: test
test: lint
	pytest -s tests/
