.PHONY: demo test lint check

demo:
	uv run mcp-guard demo

test:
	uv run pytest --cov=mcp_guard --cov-report=term-missing

lint:
	uv run ruff check .
	uv run ruff format --check .

check: lint test
