.PHONY: install test lint terraform-check verify demo

install:
	python -m pip install -e ".[dev,server]"

test:
	python -m pytest -q

protocol-test:
	python -m pytest -q tests/test_mcp_protocol.py tests/test_http_mcp_server.py

lint:
	ruff check secure_agent tests scripts

terraform-check:
	terraform fmt -check -recursive infra/terraform

verify: lint test protocol-test terraform-check

demo:
	python scripts/adversarial_demo.py
