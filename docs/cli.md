# CLI Reference

## Static Code Analysis (`scan`)

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

## Security Posture Audit (`audit`)

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
| Prompt Security | 8 | Input validation, sanitization, injection prevention |
| Model Security | 8 | Rate limiting, access controls, model protection |
| Data Privacy | 8 | PII detection, encryption, data anonymization |
| OWASP LLM Top 10 | 10 | Coverage of OWASP LLM security controls |
| Blue Team Operations | 7 | Logging, monitoring, alerting |
| Governance | 5 | Compliance, documentation, audit trails |
| Supply Chain | 3 | Dependency scanning, model provenance |
| Hallucination Mitigation | 5 | RAG implementation, confidence scoring |
| Ethical AI & Bias | 4 | Fairness metrics, explainability, bias testing |
| Incident Response | 3 | Monitoring integration, audit logging |

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

## Live Model Testing (`test`)

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
| SQLI | SQL Injection | Detects SQL injection via string formatting |

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
- **HTML**: Interactive reports with filtering, dark mode, pagination
- **SARIF**: GitHub Code Scanning, Azure DevOps, VS Code integration
