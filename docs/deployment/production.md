# Production Deployment & Setup Guide

## Quickstart (Development & Research Evaluation)

1. **Environment Setup**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   make setup
   ```

2. **Run Pytest Verification**:
   ```bash
   make test
   ```

3. **Start Core Services**:
   ```bash
   make run
   ```
   This starts:
   - CHRONOS FastAPI Server at `http://127.0.0.1:8000`
   - CHRONOS Web UI Dashboard at `http://127.0.0.1:5173`

4. **Command Line Interface**:
   ```bash
   chronos status
   chronos scan /tmp
   chronos cases
   chronos replay --host test-host
   ```

## Linux Systemd Service Installation

To run CHRONOS as a background security service on Linux:

```bash
make daemon
```

This installs `chronos.service` into systemd and enables real-time syscall observation.

## Containerized Infrastructure

For enterprise production deployments requiring Kafka event streams and persistent PostgreSQL case storage:

```bash
make docker-up
```
