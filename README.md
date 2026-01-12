# aisentry

[![Tests](https://github.com/deosha/aisentry/actions/workflows/test.yml/badge.svg)](https://github.com/deosha/aisentry/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/aisentry.svg)](https://pypi.org/project/aisentry/)
[![Downloads](https://img.shields.io/pypi/dm/aisentry.svg)](https://pypistats.org/packages/aisentry)
[![Python versions](https://img.shields.io/pypi/pyversions/aisentry.svg)](https://pypi.org/project/aisentry/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A unified command-line tool for AI/LLM security scanning. Static code analysis for OWASP LLM Top 10 vulnerabilities.

**Website**: [aisentry.co](https://aisentry.co) | **Docs**: [aisentry.co/docs](https://aisentry.co/docs.html)

## Benchmarks

Evaluated against a comprehensive OWASP LLM Top 10 testbed with 73 ground-truth vulnerabilities.

| Metric | aisentry | Semgrep | Bandit |
|--------|----------|---------|--------|
| **Precision** | 75.4% | 83.3% | 58.3% |
| **Recall** | 63.0% | 6.8% | 38.4% |
| **F1 Score** | **68.7%** | 12.7% | 46.3% |

**LLM-Specific Coverage** (patterns generic tools miss):

| Category | aisentry | Semgrep | Bandit |
|----------|----------|---------|--------|
| LLM01: Prompt Injection | 72.7% | 0% | 15.4% |
| LLM04: Model DoS | 80.0% | 0% | 0% |
| LLM06: Sensitive Info | 62.5% | 0% | 0% |
| LLM10: Model Theft | 44.4% | 0% | 0% |

> See [docs/tool_comparison.md](https://github.com/deosha/aisentry/blob/main/docs/tool_comparison.md) for detailed comparison and [llm-sec-eval](https://github.com/deosha/llm-sec-eval) for methodology.

## Features

- **Static Code Analysis**: OWASP LLM Top 10 + SQL injection detection
- **Security Posture Audit**: 61 controls across 10 categories with maturity scoring
- **Remote Scanning**: GitHub, GitLab, Bitbucket URLs
- **Multiple Outputs**: Text, JSON, HTML (interactive), SARIF (CI/CD)
- **False Positive Reduction**: ML-trained heuristics (88% accuracy)

## Installation

```bash
pip install aisentry

# With ML-based false positive reduction
pip install aisentry[ml]

# With all cloud providers
pip install aisentry[cloud]
```

## Quick Start

```bash
# Scan local project
aisentry scan ./my_project

# Scan GitHub repository
aisentry scan https://github.com/langchain-ai/langchain

# Generate HTML report
aisentry scan ./my_project -o html -f report.html

# Security posture audit
aisentry audit ./my_project
```

## Live Model Testing

For runtime testing of LLM models (prompt injection, jailbreaks), we recommend [Garak](https://github.com/leondz/garak) by NVIDIA. aisentry focuses on static code analysis - finding vulnerabilities before deployment.

## Documentation

| Topic | Link |
|-------|------|
| CLI Reference | [docs/cli.md](https://github.com/deosha/aisentry/blob/main/docs/cli.md) |
| Configuration | [docs/configuration.md](https://github.com/deosha/aisentry/blob/main/docs/configuration.md) |
| Architecture | [docs/architecture.md](https://github.com/deosha/aisentry/blob/main/docs/architecture.md) |
| CI/CD Integration | [docs/integration.md](https://github.com/deosha/aisentry/blob/main/docs/integration.md) |
| Tool Comparison | [docs/tool_comparison.md](https://github.com/deosha/aisentry/blob/main/docs/tool_comparison.md) |

## GitHub Actions

```yaml
- run: pip install aisentry
- run: aisentry scan . -o sarif -f results.sarif
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

See [docs/integration.md](https://github.com/deosha/aisentry/blob/main/docs/integration.md) for GitLab, Azure DevOps, and pre-commit examples.

## Development

```bash
git clone https://github.com/deosha/aisentry.git
cd aisentry
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- **Website**: [aisentry.co](https://aisentry.co)
- **GitHub**: [github.com/deosha/aisentry](https://github.com/deosha/aisentry)
- **PyPI**: [pypi.org/project/aisentry](https://pypi.org/project/aisentry/)
- **Issues**: [Report bugs](https://github.com/deosha/aisentry/issues)
