# Configuration

aisentry can be configured via config files, environment variables, or CLI flags.

**Precedence:** CLI flags > Environment variables > .aisentry.yaml > Defaults

## Config File (.aisentry.yaml)

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

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AISEC_MODE` | Scan mode | `recall` or `strict` |
| `AISEC_DEDUP` | Deduplication | `exact` or `off` |
| `AISEC_EXCLUDE_DIRS` | Comma-separated dirs | `vendor,third_party` |
| `AISEC_THRESHOLD` | Global threshold | `0.70` |
| `AISEC_THRESHOLD_LLM01` | Per-category threshold | `0.80` |

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
