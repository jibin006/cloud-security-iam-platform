.PHONY: install test lint terraform-check verify demo

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -q

lint:
	ruff check secure_agent tests scripts

terraform-check:
	terraform fmt -check -recursive infra/terraform

verify: lint test terraform-check

demo:
	python scripts/adversarial_demo.py
