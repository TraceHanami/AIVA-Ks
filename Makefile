.PHONY: help setup test demo lint clean docker-up docker-down

PYTHON ?= ./venv/bin/python
PYTEST ?= ./venv/bin/pytest

help:
	@echo "AIVA-KS — Developer Tooling Commands"
	@echo "======================================"
	@echo "  make setup       Install dependencies in virtualenv"
	@echo "  make test        Run full unit & integration test suite"
	@echo "  make demo        Run zero-infra end-to-end attack pipeline demo"
	@echo "  make lint        Run Python syntax & import checks"
	@echo "  make clean       Clean build artifacts, cache files, and logs"
	@echo "  make docker-up   Bring up Postgres, Kafka, Zookeeper, and API container"
	@echo "  make docker-down Stop containerized infrastructure"

setup:
	$(PYTHON) -m pip install -e .[dev,backend]

test:
	$(PYTEST) tests/ -v

demo:
	$(PYTHON) demo_full_pipeline.py

lint:
	$(PYTHON) -c "import glob, py_compile; [py_compile.compile(f, doraise=True) for f in glob.glob('**/*.py', recursive=True) if 'venv' not in f]"

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker-up:
	cd docker && docker compose up -d postgres kafka zookeeper backend

docker-down:
	cd docker && docker compose down
