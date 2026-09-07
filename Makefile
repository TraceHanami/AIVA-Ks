.PHONY: help setup test demo lint clean docker-up docker-down run-backend run-ui run

PYTHON ?= ./.venv/bin/python
PYTEST ?= ./.venv/bin/pytest

help:
	@echo "AIVA-KS — Developer Tooling Commands"
	@echo "======================================"
	@echo "  make setup       Install dependencies in virtualenv"
	@echo "  make test        Run full unit & integration test suite"
	@echo "  make demo        Run zero-infra end-to-end attack pipeline demo"
	@echo "  make run-backend Run FastAPI AI engine server on :8000"
	@echo "  make run-ui      Run React SOC Dashboard on :3000"
	@echo "  make lint        Run Python syntax & import checks"
	@echo "  make clean       Clean build artifacts, cache files, and logs"
	@echo "  make docker-up   Bring up Postgres, Kafka, Zookeeper, and API container"
	@echo "  make docker-down Stop containerized infrastructure"
	@echo "  make run         Run both backend and UI concurrently"

setup:
	$(PYTHON) -m pip install -e .[dev,backend]

test:
	$(PYTEST) tests/ -v

demo:
	$(PYTHON) demo_full_pipeline.py

run-backend:
	$(PYTHON) -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload

run-ui:
	cd frontend && npm run dev -- --host 0.0.0.0 --port 5173

run:
	@echo "Starting backend and frontend services..."
	@$(MAKE) -j 2 run-backend run-ui

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

