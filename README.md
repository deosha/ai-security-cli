# aisentry

[![Tests](https://github.com/deosha/aisentry/actions/workflows/test.yml/badge.svg)](https://github.com/deosha/aisentry/actions/workflows/test.yml)
[![PyPI version](https://badge.fury.io/py/aisentry.svg)](https://pypi.org/project/aisentry/)
[![Python versions](https://img.shields.io/pypi/pyversions/aisentry.svg)](https://pypi.org/project/aisentry/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A unified command-line tool for AI/LLM security scanning and testing. Combines static code analysis with live model testing to provide comprehensive security assessment for AI applications.

**Website**: [aisentry.co](https://aisentry.co)

## Benchmarks

Evaluated against a comprehensive OWASP LLM Top 10 testbed with 73 ground-truth vulnerabilities.

| Metric | aisentry | Semgrep | Bandit |
|--------|-----------------|---------|--------|
| **Precision** | 75.4% | 83.3% | 58.3% |
| **Recall** | 63.0% | 6.8% | 38.4% |
| **F1 Score** | **68.7%** | 12.7% | 46.3% |

**LLM-Specific Coverage** (patterns generic tools can't detect):

| Category | aisentry F1 | Semgrep | Bandit |
|----------|-----------|---------|--------|
| LLM01: Prompt Injection | 72.7% | 0% | 15.4% |
| LLM02: Insecure Output | 73.7% | 42.9% | 81.8% |
| LLM04: Model DoS | 80.0% | 0% | 0% |
| LLM06: Sensitive Info | 62.5% | 0% | 0% |
| LLM07: Insecure Plugin | 93.3% | 25.0% | 83.3% |
| LLM10: Model Theft | 44.4% | 0% | 0% |

> **Note**: Semgrep/Bandit are general-purpose SAST tools not designed for LLM patterns. Use aisentry + Bandit together for comprehensive coverage. See [llm-sec-eval](https://github.com/deosha/llm-sec-eval) for methodology and limitations.

## Features

- **Static Code Analysis**: Scan Python codebases for OWASP LLM Top 10 vulnerabilities
- **Security Posture Audit**: Auto-detect security controls and generate maturity scores across 10 categories (61 controls)
- **Remote Repository Scanning**: Scan GitHub, GitLab, and Bitbucket repositories directly via URL
- **Interactive HTML Reports**: Modern reports with tabbed interface, dark mode, severity filtering, and pagination
- **SARIF Output**: CI/CD integration with GitHub Code Scanning, Azure DevOps, VS Code, and more
- **Configurable**: YAML config files, environment variables, per-category thresholds, test file handling
- **4-Factor Confidence Scoring**: Advanced confidence calculation for accurate vulnerability assessment
- **False Positive Reduction**: ML-trained heuristics to filter common false positives (model.eval, session.exec, etc.)

## Live Model Testing

For live/runtime testing of LLM models (prompt injection, jailbreaks, etc.), we recommend [Garak](https://github.com/leondz/garak) - a comprehensive LLM vulnerability scanner by NVIDIA.

```bash
# Install Garak
pip install garak

# Run probes against a model
garak --model_type openai --model_name gpt-4 --probes all
```

aisentry focuses on **static code analysis** - finding vulnerabilities in your source code before deployment. Garak complements this by testing the **runtime behavior** of deployed models.

## Installation

```bash
# Basic installation
pip install aisentry

# With ML-based false positive reduction
pip install aisentry[ml]

# With cloud provider support
pip install aisentry[cloud]

# Development installation
pip install aisentry[dev]

# Full installation with all features
pip install aisentry[all]
```

## Configuration

### Config File (.aisentry.yaml)

Create a `.aisentry.yaml` file in your project root:

```yaml
# Scan mode: recall (high sensitivity) or strict (higher thresholds)
mode: recall

# Deduplication: exact (merge duplicates) or off
dedup: exact

# Directories to exclude
exclude_dirs:
  - vendor
  - third_party
  - node_modules

# Test file handling
exclude_tests: false
demote_tests: true
test_confidence_penalty: 0.25

# Per-category confidence thresholds
thresholds:
  LLM01: 0.70
  LLM02: 0.70
  LLM05: 0.80
  LLM06: 0.75

# Global threshold (used if category not specified)
global_threshold: 0.70
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AISEC_MODE` | Scan mode | `recall` or `strict` |
| `AISEC_DEDUP` | Deduplication | `exact` or `off` |
| `AISEC_EXCLUDE_DIRS` | Comma-separated dirs | `vendor,third_party` |
| `AISEC_THRESHOLD` | Global threshold | `0.70` |
| `AISEC_THRESHOLD_LLM01` | Per-category threshold | `0.80` |

**Precedence:** CLI flags > Environment variables > .aisentry.yaml > Defaults

## False Positive Reduction

aisentry includes ML-trained heuristics to automatically filter common false positives:

- **PyTorch `model.eval()`** - Not Python's dangerous `eval()`
- **SQLAlchemy `session.exec()`** - Not Python's dangerous `exec()`
- **Base64 images** - Not leaked API keys
- **Placeholder values** - Example/dummy credentials in docs

```bash
# FP reduction is enabled by default
aisentry scan ./my_project

# Disable FP reduction
aisentry scan ./my_project --no-fp-reduction

# Adjust threshold (0.0-1.0, default 0.4)
aisentry scan ./my_project --fp-threshold 0.5
```

For enhanced ML-based reduction, install with `pip install aisentry[ml]`. The ML model achieves 88% accuracy on labeled security findings.

## Quick Start

```bash
# Static code analysis (local)
aisentry scan ./my_project

# Static code analysis (remote GitHub repository)
aisentry scan https://github.com/langchain-ai/langchain

# Generate HTML report with Security Posture audit (default)
aisentry scan ./my_project -o html -f security_report.html

# Security posture audit only
aisentry audit ./my_project

# Live model testing
export OPENAI_API_KEY=sk-...
aisentry test -p openai -m gpt-4 --mode quick
```

## HTML Report Features

The HTML reports include a modern, interactive interface:

- **Tabbed Interface**: Switch between Vulnerabilities and Security Posture views
- **Dark Mode**: Toggle between light and dark themes (persists in browser)
- **Severity Filtering**: Click severity buttons to filter by Critical, High, Medium, Low
- **Pagination**: "Show More" button loads items in batches of 10
- **Combined Scoring**: See both vulnerability score and security posture score
- **Hover Effects**: Cards and items highlight on hover for better UX

## Architecture

### High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                     AISENTRY                                          │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                       │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐                      │
│  │  scan command  │    │ audit command  │    │  test command  │                      │
│  └───────┬────────┘    └───────┬────────┘    └───────┬────────┘                      │
│          │                     │                     │                                │
│          ▼                     ▼                     ▼                                │
│  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐                   │
│  │  STATIC ANALYSIS  │ │  SECURITY AUDIT   │ │   LIVE TESTING    │                   │
│  │                   │ │                   │ │                   │                   │
│  │ • AST Parser      │ │ • 61 Controls     │ │ • 7 LLM Providers │                   │
│  │ • 10 OWASP Detect │ │ • 10 Categories   │ │ • 11 Detectors    │                   │
│  │ • 7 Scorers       │ │ • Maturity Score  │ │ • 4-Factor Conf.  │                   │
│  └─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘                   │
│            │                     │                     │                              │
│            └─────────────────────┼─────────────────────┘                              │
│                                  ▼                                                    │
│                    ┌──────────────────────────────┐                                  │
│                    │      REPORT GENERATION       │                                  │
│                    │  JSON | HTML | SARIF | Text  │                                  │
│                    │                              │                                  │
│                    │  HTML Features:              │                                  │
│                    │  • Tabbed Interface          │                                  │
│                    │  • Dark Mode Toggle          │                                  │
│                    │  • Severity Filtering        │                                  │
│                    │  • Pagination                │                                  │
│                    └──────────────────────────────┘                                  │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Static Analysis Flow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           STATIC ANALYSIS PIPELINE                                │
└──────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐      ┌─────────────┐      ┌────────────────────────────────────────┐
  │ Python  │      │  AST Parser │      │         10 OWASP DETECTORS             │
  │  Code   │─────▶│  & Pattern  │─────▶│                                        │
  │ (.py)   │      │  Extractor  │      │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
  └─────────┘      └─────────────┘      │  │  LLM01   │ │  LLM02   │ │ LLM03  │ │
                                        │  │  Prompt  │ │ Insecure │ │Training│ │
                                        │  │ Injection│ │  Output  │ │Poison  │ │
                                        │  └──────────┘ └──────────┘ └────────┘ │
                                        │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
                                        │  │  LLM04   │ │  LLM05   │ │ LLM06  │ │
                                        │  │Model DoS │ │  Supply  │ │Secrets │ │
                                        │  │          │ │  Chain   │ │        │ │
                                        │  └──────────┘ └──────────┘ └────────┘ │
                                        │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
                                        │  │  LLM07   │ │  LLM08   │ │ LLM09  │ │
                                        │  │ Insecure │ │Excessive │ │  Over  │ │
                                        │  │  Plugin  │ │ Agency   │ │reliance│ │
                                        │  └──────────┘ └──────────┘ └────────┘ │
                                        │  ┌──────────┐                         │
                                        │  │  LLM10   │                         │
                                        │  │  Model   │                         │
                                        │  │  Theft   │                         │
                                        │  └──────────┘                         │
                                        └───────────────────┬────────────────────┘
                                                            │
                                                            ▼
  ┌────────────────────────────────────────────────────────────────────────────────┐
  │                            7 SECURITY SCORERS                                   │
  │                                                                                 │
  │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
  │   │  Prompt  │ │  Model   │ │   Data   │ │Hallucin- │ │ Ethical  │            │
  │   │ Security │ │ Security │ │ Privacy  │ │  ation   │ │    AI    │            │
  │   └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
  │   ┌──────────┐ ┌──────────┐                                                    │
  │   │Governance│ │  OWASP   │                                                    │
  │   │          │ │  Score   │                                                    │
  │   └──────────┘ └──────────┘                                                    │
  └───────────────────────────────────────────┬────────────────────────────────────┘
                                              │
                                              ▼
                            ┌─────────────────────────────────┐
                            │          SCAN RESULT            │
                            │  • Findings    • Category Scores│
                            │  • Overall Score  • Confidence  │
                            └─────────────────────────────────┘
```

### Live Testing Flow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            LIVE TESTING PIPELINE                                  │
└──────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────┐
│                              7 LLM PROVIDERS                                    │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ ┌─────┐│
│  │ OpenAI  │ │Anthropic│ │ AWS     │ │ Google  │ │  Azure  │ │Ollama │ │Cust-││
│  │         │ │         │ │ Bedrock │ │ Vertex  │ │ OpenAI  │ │(local)│ │ om  ││
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───┬───┘ └──┬──┘│
└───────┴──────────┴──────────┴──────────┴──────────┴─────────┴────────┴──────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │    BASELINE QUERIES      │
                          └────────────┬─────────────┘
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                            11 LIVE DETECTORS                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│
│  │  Prompt  │ │Jailbreak │ │   Data   │ │ Halluc-  │ │   DoS    │ │   Bias   ││
│  │Injection │ │          │ │ Leakage  │ │ ination  │ │          │ │Detection ││
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘│
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │  Model   │ │Adversar- │ │  Output  │ │  Supply  │ │Behavioral│            │
│  │Extraction│ │   ial    │ │  Manip.  │ │  Chain   │ │ Anomaly  │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
└───────────────────────────────────────────┬────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                        4-FACTOR CONFIDENCE CALCULATION                          │
│                                                                                 │
│    Response Analysis (30%) + Detector Logic (35%) +                            │
│    Evidence Quality (25%) + Severity Factor (10%) = Confidence Score           │
└───────────────────────────────────────────┬────────────────────────────────────┘
                                            │
                                            ▼
                          ┌─────────────────────────────────┐
                          │          TEST RESULT            │
                          │  • Vulnerabilities  • Score     │
                          │  • Tests Passed   • Confidence  │
                          └─────────────────────────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           aisentry package                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                           CLI LAYER (cli.py)                             │    │
│  │    scan command ─────────────────────────── test command                 │    │
│  └─────────┬───────────────────────────────────────────┬───────────────────┘    │
│            │                                           │                         │
│            ▼                                           ▼                         │
│  ┌──────────────────────────┐            ┌──────────────────────────┐           │
│  │      scanner.py          │            │       tester.py          │           │
│  └────────────┬─────────────┘            └────────────┬─────────────┘           │
│               │                                       │                          │
│      ┌────────┴────────┐                    ┌─────────┴─────────┐               │
│      ▼                 ▼                    ▼                   ▼               │
│  ┌────────────┐  ┌────────────┐      ┌────────────┐    ┌────────────┐          │
│  │  STATIC    │  │  SCORERS   │      │   LIVE     │    │ PROVIDERS  │          │
│  │ DETECTORS  │  │            │      │ DETECTORS  │    │            │          │
│  │ LLM01-10   │  │ 7 scorers  │      │ 11 detects │    │ 7 providers│          │
│  └────────────┘  └────────────┘      └────────────┘    └────────────┘          │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  REPORTERS: base | json | html | sarif                                   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  MODELS: finding.py | vulnerability.py | result.py                       │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  UTILS: markov_chain | entropy | scoring | statistical                   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## CLI Commands

### Static Code Analysis (`scan`)

Scan Python code for OWASP LLM Top 10 vulnerabilities. Supports local files/directories and remote Git repositories.

```bash
aisentry scan <path> [OPTIONS]
```

**Path Options:**

| Path Type | Example |
|-----------|---------|
| Local file | `./app.py` |
| Local directory | `./my_project` |
| GitHub URL | `https://github.com/user/repo` |
| GitLab URL | `https://gitlab.com/user/repo` |
| Bitbucket URL | `https://bitbucket.org/user/repo` |

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output format: text, json, html, sarif | text |
| `-f, --output-file` | Write output to file | - |
| `-s, --severity` | Minimum severity: critical, high, medium, low, info | info |
| `-c, --confidence` | Minimum confidence threshold (0.0-1.0) | 0.7 |
| `--category` | Filter by OWASP category (LLM01-LLM10) | all |
| `--audit/--no-audit` | Include security posture audit in HTML reports | true |
| `--config` | Path to .aisentry.yaml config file | auto-detect |
| `--mode` | Scan mode: recall (sensitive) or strict (precise) | recall |
| `--dedup` | Deduplication: exact (merge) or off | exact |
| `--exclude-dir` | Directories to exclude (repeatable) | - |
| `--exclude-tests` | Skip test files entirely | false |
| `--demote-tests` | Reduce confidence for test file findings | true |
| `--fp-reduction/--no-fp-reduction` | Enable/disable false positive filtering | true |
| `--fp-threshold` | Minimum TP probability to keep findings (0.0-1.0) | 0.4 |
| `-v, --verbose` | Enable verbose output | false |

**Examples:**

```bash
# Scan a local project directory
aisentry scan ./my_llm_app

# Scan with JSON output
aisentry scan ./app.py -o json -f results.json

# Scan for high severity issues only
aisentry scan ./project -s high

# Scan specific OWASP categories
aisentry scan ./project --category LLM01 --category LLM02

# Generate HTML report
aisentry scan ./project -o html -f security_report.html

# Scan a GitHub repository directly
aisentry scan https://github.com/langchain-ai/langchain

# Generate HTML without security posture audit
aisentry scan ./project -o html --no-audit -f vuln-only.html
```

### Security Posture Audit (`audit`)

Evaluate security controls and maturity level of your codebase. Detects 61 security controls across 10 categories.

```bash
aisentry audit <path> [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output format: text, json, html | text |
| `-f, --output-file` | Write output to file | - |
| `-v, --verbose` | Enable verbose output | false |

**Security Control Categories:**

| Category | Controls | Description |
|----------|----------|-------------|
| Prompt Security | 8 | Input validation, sanitization, injection prevention, red teaming |
| Model Security | 8 | Rate limiting, access controls, model protection, differential privacy |
| Data Privacy | 8 | PII detection, encryption, data anonymization, GDPR compliance |
| OWASP LLM Top 10 | 10 | Coverage of OWASP LLM security controls |
| Blue Team Operations | 7 | Logging, monitoring, alerting, drift detection |
| Governance | 5 | Compliance, documentation, audit trails |
| Supply Chain | 3 | Dependency scanning, model provenance, integrity verification |
| Hallucination Mitigation | 5 | RAG implementation, confidence scoring, fact checking |
| Ethical AI & Bias | 4 | Fairness metrics, explainability, bias testing, model cards |
| Incident Response | 3 | Monitoring integration, audit logging, rollback capability |

**Maturity Levels:**

| Level | Score | Description |
|-------|-------|-------------|
| Initial | 0-20 | No formal security controls |
| Developing | 21-40 | Basic controls being implemented |
| Defined | 41-60 | Documented security processes |
| Managed | 61-80 | Measured and controlled security |
| Optimizing | 81-100 | Continuous security improvement |

**Examples:**

```bash
# Audit a local project
aisentry audit ./my_project

# Generate HTML audit report
aisentry audit ./project -o html -f audit-report.html

# Audit a GitHub repository
aisentry audit https://github.com/user/repo -o json
```

### Live Model Testing (`test`)

Test live LLM models for security vulnerabilities.

```bash
aisentry test [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --provider` | LLM provider (required) | - |
| `-m, --model` | Model name (required) | - |
| `-e, --endpoint` | Custom endpoint URL | - |
| `-t, --tests` | Specific tests to run | all |
| `--mode` | Testing depth: quick, standard, comprehensive | standard |
| `-o, --output` | Output format: text, json, html, sarif | text |
| `-f, --output-file` | Write output to file | - |
| `--timeout` | Timeout per test in seconds | 30 |
| `-v, --verbose` | Enable verbose output | false |

**Supported Providers:**

| Provider | Environment Variables |
|----------|----------------------|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `bedrock` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| `vertex` | `GOOGLE_APPLICATION_CREDENTIALS` |
| `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| `ollama` | None (local) |
| `custom` | `CUSTOM_API_KEY` (optional) |

**Examples:**

```bash
# Quick test with OpenAI
export OPENAI_API_KEY=sk-...
aisentry test -p openai -m gpt-4 --mode quick

# Comprehensive test with Anthropic
export ANTHROPIC_API_KEY=...
aisentry test -p anthropic -m claude-3-opus --mode comprehensive

# Test specific vulnerabilities
aisentry test -p openai -m gpt-4 -t prompt-injection -t jailbreak

# Test with Ollama (local)
aisentry test -p ollama -m llama2 --mode standard
```

## OWASP LLM Top 10 Coverage

### Static Analysis Detectors

| ID | Vulnerability | Description |
|----|---------------|-------------|
| LLM01 | Prompt Injection | Detects unsanitized user input in prompts |
| LLM02 | Insecure Output Handling | Identifies unvalidated LLM output |
| LLM03 | Training Data Poisoning | Finds unsafe data loading |
| LLM04 | Model Denial of Service | Detects missing rate limiting |
| LLM05 | Supply Chain Vulnerabilities | Identifies unsafe model loading |
| LLM06 | Sensitive Information Disclosure | Finds hardcoded secrets |
| LLM07 | Insecure Plugin Design | Detects unsafe plugin loading |
| LLM08 | Excessive Agency | Identifies autonomous actions |
| LLM09 | Overreliance | Finds missing output validation |
| LLM10 | Model Theft | Detects exposed model artifacts |

### Live Testing Detectors

| ID | Detector | Description |
|----|----------|-------------|
| PI | Prompt Injection | Tests for injection vulnerabilities |
| JB | Jailbreak | Tests for instruction bypass attacks |
| DL | Data Leakage | Tests for PII exposure |
| HAL | Hallucination | Tests for factual accuracy |
| DOS | Denial of Service | Tests for resource exhaustion |
| BIAS | Bias Detection | Tests for demographic bias |
| ME | Model Extraction | Tests for architecture disclosure |
| ADV | Adversarial Inputs | Tests for encoding attacks |
| OM | Output Manipulation | Tests for response injection |
| SC | Supply Chain | Tests for unsafe code generation |
| BA | Behavioral Anomaly | Tests for unexpected behavior |

## Output Formats

- **Text**: Human-readable terminal output
- **JSON**: Machine-readable format for CI/CD
- **HTML**: Interactive reports with filtering
- **SARIF**: GitHub Code Scanning, Azure DevOps, VS Code integration

## Integration

### GitHub Actions

```yaml
name: aisentry Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install aisentry
      - run: aisentry scan . -o sarif -f results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: aisentry-scan
        name: aisentry Security Scan
        entry: aisentry scan
        language: system
        types: [python]
        args: ['-s', 'high']
```

## Development

```bash
git clone https://github.com/deosha/aisentry.git
cd aisentry
pip install -e ".[dev]"
pytest tests/ -v --cov=aisentry
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- **Website**: [aisentry.co](https://aisentry.co)
- **GitHub**: [github.com/deosha/aisentry](https://github.com/deosha/aisentry)
- **PyPI**: [pypi.org/project/aisentry](https://pypi.org/project/aisentry/)
- **Issues**: [Report bugs](https://github.com/deosha/aisentry/issues)
