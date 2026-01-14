# AISentry Detector Evaluation Report

## Summary Comparison

| Method | Precision | Recall | F1 | Critical Recall | TP | FP |
|--------|-----------|--------|----|-----------------|----|----| 
| ensemble | 0.857 | 1.000 | 0.923 (+0.0%) | 1.000 | 30 | 5 |
| ml_only | 0.857 | 1.000 | 0.923 (+0.0%) | 1.000 | 30 | 5 |
| pattern_only | 0.857 | 1.000 | 0.923 | 1.000 | 30 | 5 |
| taint_only | 0.857 | 1.000 | 0.923 (+0.0%) | 1.000 | 30 | 5 |

## Detailed Results


### pattern_only


## Evaluation Results

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 1.000 |
| F1 Score | 0.923 |
| Accuracy | 0.875 |
| Critical Recall | 1.000 |

### Confusion Matrix
|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **Actual Positive** | 30 (TP) | 0 (FN) |
| **Actual Negative** | 5 (FP) | 5 (TN) |

### Detection by Category
| Category | Detection Rate |
|----------|----------------|
| LLM01 | 0.0% |

### Performance
- Total scan time: 0.74s
- Files scanned: 40
- Avg time per file: 18.6ms


### ml_only


## Evaluation Results

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 1.000 |
| F1 Score | 0.923 |
| Accuracy | 0.875 |
| Critical Recall | 1.000 |

### Confusion Matrix
|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **Actual Positive** | 30 (TP) | 0 (FN) |
| **Actual Negative** | 5 (FP) | 5 (TN) |

### Detection by Category
| Category | Detection Rate |
|----------|----------------|
| LLM01 | 0.0% |

### Performance
- Total scan time: 1.09s
- Files scanned: 40
- Avg time per file: 27.3ms


### taint_only


## Evaluation Results

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 1.000 |
| F1 Score | 0.923 |
| Accuracy | 0.875 |
| Critical Recall | 1.000 |

### Confusion Matrix
|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **Actual Positive** | 30 (TP) | 0 (FN) |
| **Actual Negative** | 5 (FP) | 5 (TN) |

### Detection by Category
| Category | Detection Rate |
|----------|----------------|
| LLM01 | 0.0% |

### Performance
- Total scan time: 0.73s
- Files scanned: 40
- Avg time per file: 18.3ms


### ensemble


## Evaluation Results

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 1.000 |
| F1 Score | 0.923 |
| Accuracy | 0.875 |
| Critical Recall | 1.000 |

### Confusion Matrix
|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **Actual Positive** | 30 (TP) | 0 (FN) |
| **Actual Negative** | 5 (FP) | 5 (TN) |

### Detection by Category
| Category | Detection Rate |
|----------|----------------|
| LLM01 | 0.0% |

### Performance
- Total scan time: 0.97s
- Files scanned: 40
- Avg time per file: 24.3ms
