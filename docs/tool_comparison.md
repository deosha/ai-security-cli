# Security Scanner Comparison: aisentry vs Bandit vs Semgrep

Comparison performed on 3 real-world LLM/AI repositories:
- **chatgpt-retrieval-plugin** (OpenAI)
- **private-gpt** (Zylon)
- **chat-langchain** (LangChain)

## Summary Table

| Repository | aisentry | Bandit | Semgrep |
|------------|----------|--------|---------|
| chatgpt-retrieval-plugin | 13 | 343 | 27 |
| private-gpt | 11 | 88 | 3 |
| chat-langchain | 3 | 3 | 2 |
| **Total** | **27** | **434** | **32** |

## False Positive Breakdown

| Metric | aisentry | Bandit | Semgrep |
|--------|----------|--------|---------|
| **Total Findings** | 27 | 434 | 32 |
| **False Positives** | 0 | 410 | 19 |
| **Actionable** | 27 | 24 | 13 |
| **FP Rate** | 0% | 94.5% | 59.4% |
| **Precision** | 100% | 5.5% | 40.6% |

### False Positive Details

| Tool | FP Type | Count | Description |
|------|---------|-------|-------------|
| Bandit | B101 assert_used | 408 | Assert statements in test/production code |
| Bandit | B105/B106 credentials | 2 | `<\|endoftext\|>` (LLM stop token), `secret-key` (placeholder) |
| Semgrep | detected-jwt-token | 4 | Example tokens in documentation (setup.md, notebooks) |
| Semgrep | Docker warnings | 10 | Container hardening suggestions (no-new-privileges, writable-filesystem) |
| Semgrep | Other noise | 5 | Low-priority config warnings |
| aisentry | - | 0 | No false positives |

## Finding Categories

### aisentry Findings by Category

| Category | chatgpt-retrieval | private-gpt | chat-langchain |
|----------|-------------------|-------------|----------------|
| SQL Injection | 12 | 1 | 0 |
| LLM04: Model DoS | 1 | 2 | 1 |
| LLM10: Model Theft | 0 | 6 | 0 |
| LLM09: Overreliance | 0 | 2 | 1 |
| LLM02: Insecure Output | 0 | 0 | 1 |

### Bandit Findings by Rule (Non-B101)

| Rule | Description | chatgpt-retrieval | private-gpt | chat-langchain |
|------|-------------|-------------------|-------------|----------------|
| B608 | SQL Injection | 10 | 0 | 0 |
| B104 | Bind all interfaces | 3 | 1 | 0 |
| B105/B106 | Hardcoded credentials | 0 | 2 (FP) | 0 |
| B603/B607 | Subprocess issues | 0 | 4 | 0 |
| B311 | Random (test files) | 2 | 0 | 0 |
| B108 | Temp file usage | 1 | 0 | 0 |

### Semgrep Findings by Rule

| Rule | chatgpt-retrieval | private-gpt | chat-langchain |
|------|-------------------|-------------|----------------|
| sqlalchemy-execute-raw-query | 9 | 0 | 0 |
| formatted-sql-query | 3 | 0 | 0 |
| detected-jwt-token | 4 | 0 | 0 |
| Docker warnings | 10 | 0 | 0 |
| Other | 1 | 3 | 2 |

## Key Differentiators

### What aisentry Catches That Others Miss
- **LLM04 (Model Denial of Service)**: Unbounded token limits, missing rate limiting
- **LLM10 (Model Theft)**: Exposed model endpoints without authentication
- **LLM09 (Overreliance)**: Missing output validation on LLM responses
- **LLM02 (Insecure Output Handling)**: Direct execution of LLM output

### What Bandit Catches
- Traditional security issues (subprocess, temp files, bind interfaces)
- SQL injection (overlaps with aisentry)
- Generates significant noise from B101 (assert statements)

### What Semgrep Catches
- SQL injection patterns
- Docker/container security misconfigurations
- Secrets in documentation (often false positives)

## Conclusion

| Metric | aisentry | Bandit | Semgrep |
|--------|----------|--------|---------|
| Signal-to-Noise Ratio | 100% | 5.5% | ~40% |
| LLM-Specific Coverage | Yes | No | No |
| False Positive Rate | 0% | 94.5% | ~60% |
| Focus | OWASP LLM Top 10 | General Python | Multi-language |

**aisentry** is purpose-built for AI/LLM applications and provides:
- Zero false positives in this benchmark
- LLM-specific vulnerability detection
- High signal-to-noise ratio
- Actionable findings for AI security
