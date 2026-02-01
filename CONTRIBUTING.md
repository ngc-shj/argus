# Contributing to Argus

Thank you for your interest in contributing to Argus!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ngc-shj/argus.git
   cd argus
   ```

2. Install dependencies with uv:
   ```bash
   uv sync --all-extras
   ```

3. Install pre-commit hooks:
   ```bash
   uv run pre-commit install
   ```

## Development Workflow

### Running Tests

```bash
uv run pytest
```

With coverage:
```bash
uv run pytest --cov=src/argus
```

### Linting and Formatting

```bash
# Run linter
uv run ruff check src/

# Auto-fix linting issues
uv run ruff check --fix src/

# Format code
uv run ruff format src/
```

### Type Checking

```bash
uv run mypy src/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure all tests pass and linting is clean
5. Commit your changes with a descriptive message
6. Push to your fork
7. Open a Pull Request

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove, etc.)
- Keep the first line under 72 characters

Examples:
- `Add subdomain enumeration to DNS scanner`
- `Fix timeout handling in port scanner`
- `Update Anthropic provider for new API version`

## Code Style

- Follow PEP 8 guidelines (enforced by Ruff)
- Use type hints for all function parameters and return values
- Write docstrings for public functions and classes
- Keep functions focused and single-purpose

## Adding New Scanners

To add a new scanner module:

1. Create a new directory under `src/argus/scanners/`
2. Implement the `IScanner` interface from `src/argus/core/interfaces.py`
3. Add corresponding Pydantic models in `src/argus/models/`
4. Register the scanner in `src/argus/orchestration/coordinator.py`
5. Add tests in `tests/`

## Questions?

Feel free to open an issue for any questions or suggestions.
