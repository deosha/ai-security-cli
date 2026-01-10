# Contributing to aisentry

Thank you for your interest in contributing to aisentry! This document provides guidelines and information for contributors.

## Ways to Contribute

### 1. Report Issues
- **Bug reports**: Include steps to reproduce, expected vs actual behavior, and environment details
- **Feature requests**: Describe the use case and proposed solution
- **False positives/negatives**: Help us improve detection accuracy

### 2. Improve Documentation
- Fix typos or unclear explanations
- Add examples and use cases
- Translate documentation

### 3. Submit Code
- Fix bugs
- Add new detectors
- Improve existing detectors
- Add support for new languages

## Development Setup

```bash
# Clone the repository
git clone https://github.com/deosha/aisentry.git
cd aisentry

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
ruff check src/
black --check src/
```

## Project Structure

```
aisentry/
├── src/aisentry/
│   ├── cli.py                 # CLI entry point
│   ├── config.py              # Configuration management
│   ├── core/
│   │   ├── scanner.py         # Static analysis orchestrator
│   │   └── tester.py          # Live testing orchestrator
│   ├── static_detectors/      # OWASP LLM Top 10 detectors
│   │   ├── base_detector.py   # Base class for detectors
│   │   ├── llm01_prompt_injection.py
│   │   ├── llm02_insecure_output.py
│   │   └── ...
│   ├── live_detectors/        # Runtime testing detectors
│   ├── providers/             # LLM provider integrations
│   ├── reporters/             # Output formatters (HTML, JSON, SARIF)
│   └── audit/                 # Security posture audit system
└── tests/
```

## Adding a New Static Detector

1. Create a new file in `src/aisentry/static_detectors/`:

```python
# llm99_new_category.py
from .base_detector import BaseDetector
from ..models.finding import Finding, Severity

class LLM99NewCategoryDetector(BaseDetector):
    """Detector for LLM99: New Category."""

    detector_id = "LLM99"
    detector_name = "New Category"
    description = "Detects new category vulnerabilities"

    def detect(self, ast_tree, source_code: str, file_path: str) -> list[Finding]:
        findings = []

        # Your detection logic here
        # Use AST visitors to find vulnerable patterns

        return findings
```

2. Register it in `src/aisentry/static_detectors/__init__.py`

3. Add tests in `tests/static_detectors/test_llm99.py`

4. Add test cases to the testbed at `../llm-sec-eval/testbed/llm99_new_category/`

## Improving Detection Accuracy

We track precision and recall against a ground truth testbed. Current metrics:
- **Precision**: 75.4%
- **Recall**: 63.0%
- **F1 Score**: 68.7%

See [llm-sec-eval](https://github.com/deosha/llm-sec-eval) for full evaluation methodology.

### Reducing False Positives

1. Add patterns to safe function allowlists
2. Improve AST context analysis (is this actually user input?)
3. Add semantic understanding (is this a test file? logging?)

### Improving Recall

1. Add new detection patterns
2. Handle edge cases in existing detectors
3. Add support for framework-specific patterns

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/static_detectors/test_llm01.py -v

# Run with coverage
pytest tests/ -v --cov=aisentry --cov-report=html

# Validate against testbed
cd ../llm-sec-eval
python3 scripts/aggregate_static.py
```

## Code Style

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type hints**: Encouraged but not required
- **Docstrings**: Required for public APIs

```bash
# Format code
black src/ tests/

# Check linting
ruff check src/ tests/

# Fix auto-fixable issues
ruff check --fix src/ tests/
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make changes** and add tests
4. **Run tests**: `pytest tests/ -v`
5. **Run linting**: `ruff check src/ && black --check src/`
6. **Commit**: Use clear, descriptive commit messages
7. **Push**: `git push origin feature/my-feature`
8. **Open PR**: Describe what changes you made and why

### PR Checklist

- [ ] Tests pass locally
- [ ] Linting passes
- [ ] Added/updated tests for new functionality
- [ ] Updated documentation if needed
- [ ] PR description explains the changes

## Good First Issues

Look for issues labeled `good-first-issue` on GitHub. These are specifically chosen to be approachable for new contributors:

- Adding safe function patterns to reduce false positives
- Improving error messages
- Adding test cases
- Documentation improvements

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make aisentry better!
