.PHONY: help setup test demo lint clean docker-up docker-down run-backend run-ui run daemon cli boot-scan

VENV ?= $(CURDIR)/.venv
PYTHON ?= $(shell if [ -f $(VENV)/bin/python ]; then echo $(VENV)/bin/python; else which python3; fi)
PYTEST ?= $(shell if [ -f $(VENV)/bin/pytest ]; then echo $(VENV)/bin/pytest; else which pytest; fi)

help:
	@echo "CHRONOS — Cyber Threat Understanding & Response Operating System"
	@echo "=================================================================="
	@echo "  make setup       Install dependencies in virtualenv"
	@echo "  make test        Run full unit, integration, and e2e test suite"
	@echo "  make cli         Run CHRONOS CLI status check"
	@echo "  make boot-scan   Run Linux/Ubuntu initial boot security audit"
	@echo "  make run-backend Run FastAPI CHRONOS engine server on :8000"
	@echo "  make run-ui      Run React/Vite SOC Dashboard on :5173"
	@echo "  make run         Run both backend and UI concurrently"
	@echo "  make lint        Run Python syntax & import checks"
	@echo "  make clean       Clean build artifacts, cache files, and logs"
	@echo "  make docker-up   Bring up Postgres, Kafka, Zookeeper, and API container"
	@echo "  make docker-down Stop containerized infrastructure"
	@echo "  make daemon      Install & start as systemd Linux Defender service"

setup:
	$(PYTHON) -m pip install -e .[dev,backend]
	@if command -v npm >/dev/null 2>&1 && [ -d frontend ]; then \
		echo "[*] Installing frontend node packages..."; \
		(cd frontend && npm install); \
	fi

test:
	$(PYTEST) tests/ -v

cli:
	$(VENV)/bin/chronos status

boot-scan:
	$(PYTHON) -m chronos.intelligence.boot_scanner

run-backend:
	$(PYTHON) -m uvicorn chronos.api.app:app --host 0.0.0.0 --port 8000 --reload

run-ui:
	@if command -v npm >/dev/null 2>&1; then \
		if [ ! -d frontend/node_modules ]; then \
			echo "[*] Initializing frontend dependencies (npm install)..."; \
			(cd frontend && npm install); \
		fi; \
		cd frontend && npm run dev -- --host 0.0.0.0 --port 5173; \
	else \
		echo "[!] Node.js / npm is not installed. To use the Web UI dashboard, install npm via: sudo apt install -y nodejs npm"; \
	fi

run:
	@echo "Starting backend and frontend services..."
	@$(MAKE) -j 2 run-backend run-ui

daemon:
	@sudo ./install_ubuntu_daemon.sh

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
