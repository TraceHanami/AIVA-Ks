# Contributing to AIVA-KS

Thank you for your interest in contributing to **AIVA-KS**! We welcome contributions to kernel security telemetry, graph algorithms, explainability engines, and visualization UI.

---

## 🛠️ Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/aiva-ks.git
   cd aiva-ks
   ```

2. **Set up virtual environment & install dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   make setup
   ```

3. **Run the demo pipeline & test suite**:
   ```bash
   make demo
   make test
   ```

---

## 🧪 Testing Guidelines

* Write unit/integration tests under the `tests/` directory for any new features or graph algorithms.
* Ensure all existing tests pass before creating a pull request:
  ```bash
  make test
  ```

---

## 🎨 Code Style

* Follow PEP 8 guidelines for Python code.
* Run `make lint` to verify syntax and imports across all modules.

---

## 📜 Commit Message Conventions

Use clear, descriptive commit messages:
- `feat(graph): add temporal decay factor to risk propagation`
- `fix(mitre): correct confidence scoring threshold for T1055`
- `docs: update system architecture diagram in README`
