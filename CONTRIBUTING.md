# Contributing Guidelines

Thank you for considering contributing to `technitium-sophos-sync`!

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/jelmervdm/technitium-sophos-sync.git
   cd technitium-sophos-sync
   ```

2. Create a virtual environment and install development dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Ensure tests and linting pass before submitting a pull request:
   ```bash
   pytest
   mypy src tests
   ruff check src tests
   ```

## Pull Request Guidelines

- Ensure your code adheres to Python 3.11+ type hints and PEP 8 style standards.
- Add unit tests for new functionality or bug fixes.
- Keep commits clear and descriptive.
