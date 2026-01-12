"""
FP Reducer - Heuristic-based false positive reduction for aisentry

This module filters likely false positives using pattern matching and heuristics.
By default, only rule-based heuristics are active. Optional ML and LLM modes
require additional setup.

Approaches:
1. Rule-based heuristics (default, always active):
   - Detects session.exec() vs Python exec()
   - Detects model.eval() vs Python eval()
   - Filters placeholder/example values
   - Reduces confidence for test/docs/vendor files

2. ML classifier (optional, requires scikit-learn + training data):
   - Train with labeled findings via FPReducer.train()
   - Load saved model via model_path parameter

3. LLM verification (optional, requires ANTHROPIC_API_KEY):
   - Only used for HIGH/CRITICAL findings above threshold
   - Adds cost per verification call

Usage:
    from aisentry.fp_reducer import FPReducer

    # Default: heuristics only
    reducer = FPReducer()
    filtered = reducer.filter_findings(findings, threshold=0.4)

    # With ML model
    reducer = FPReducer(use_ml=True, model_path="fp_model.pkl")

    # With LLM verification for high-severity
    reducer = FPReducer(use_llm=True, llm_threshold=0.5)
"""

import json
import os
import pickle
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional imports
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


@dataclass
class Finding:
    """Represents a security finding from aisentry scan"""
    id: str
    category: str
    severity: str
    confidence: float
    description: str
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# Known false positive patterns
FP_PATTERNS = {
    # SQLAlchemy session.exec() is not Python exec()
    'session_exec': [
        r'session\.exec\s*\(',
        r'session\.execute\s*\(',
        r'db\.session\.exec',
    ],
    # PyTorch model.eval() is not Python eval()
    'model_eval': [
        r'model\.eval\s*\(',
        r'\.eval\(\)\s*#.*torch',
        r'torch.*\.eval\(',
    ],
    # Base64 encoded images, not leaked secrets
    'base64_image': [
        r'data:image/[a-z+]+;base64,',  # Handles svg+xml, png, etc.
        r'base64.*(?:png|jpg|jpeg|svg|gif)',
        r'data:image/',  # Any data:image URI
    ],
    # Placeholder/example values
    'placeholder': [
        r'your[-_]?(?:api[-_]?)?(?:key|secret|token)',
        r'(?:example|placeholder|dummy|test)[-_]?(?:key|secret|token)',
        r'sk[-_](?:test|example|xxx+)',
        r'xxx+',
        r'<your[-_]',
        r'\$\{.*(?:KEY|SECRET|TOKEN)\}',
    ],
    # Environment variable references (not actual secrets)
    'env_reference': [
        r'os\.(?:environ|getenv)\s*\[?\s*["\']',
        r'process\.env\.',
        r'\$\{[A-Z_]+\}',
    ],
    # Python stdlib/async patterns (not LLM output execution)
    'async_run': [
        r'asyncio\.run\s*\(',
        r'loop\.run_until_complete\s*\(',
        r'await\s+\w+\.run\s*\(',
    ],
    # Class inheritance patterns (not LLM execution)
    'super_run': [
        r'super\(\)\.run\s*\(',
        r'super\(\w+,\s*\w+\)\.run\s*\(',
        r'self\._run\s*\(',
    ],
    # Server/runner frameworks (not LLM output)
    'server_runner': [
        r'uvicorn\.run\s*\(',
        r'uvloop\.run\s*\(',
        r'gunicorn',
        r'hypercorn\.run',
        r'daphne\.run',
    ],
    # LangChain/framework internal patterns
    'framework_internal': [
        r'RunnableMap\s*\(',
        r'RunnableSequence',
        r'RunnableLambda',
        r'\|\s*parser',
        r'langchain.*\.invoke\s*\(',
        r'llama_index.*\.invoke\s*\(',
    ],
    # Executor pool patterns (not LLM execution)
    'executor_pool': [
        r'ThreadPoolExecutor',
        r'ProcessPoolExecutor',
        r'concurrent\.futures',
        r'\.submit\s*\(',
    ],
    # Build/CI tool subprocess calls
    'build_tools': [
        r'pip\s+install',
        r'poetry\s+install',
        r'npm\s+install',
        r'yarn\s+install',
        r'\bpytest\b',
        r'python\s+setup\.py',
        r'\bmake\s+(?:build|install|test|clean|all)\b',
        r'git\s+clone',
    ],
    # Callback/handler patterns (framework design)
    'callback_handler': [
        r'callback.*handler',
        r'on_\w+_start',
        r'on_\w+_end',
        r'run_manager',
        r'CallbackManager',
    ],
}

# File path patterns that indicate lower risk
LOW_RISK_PATHS = [
    r'/tests?/',
    r'/test_',
    r'_test\.py$',
    r'/examples?/',
    r'/docs?/',
    r'/fixtures?/',
    r'/mocks?/',
    r'/vendor/',
    r'/node_modules/',
    r'\.test\.[jt]sx?$',
    r'\.spec\.[jt]sx?$',
    r'/demo/',
    r'/sample/',
]

# Category risk weights (higher = more likely to be real vulnerability)
CATEGORY_RISK = {
    'LLM01': 0.7,  # Prompt Injection - high risk, core OWASP LLM vulnerability
    'LLM02': 0.7,  # Insecure Output Handling - usually real
    'LLM03': 0.5,  # Training Data Poisoning
    'LLM04': 0.2,  # Model Denial of Service - often FP in frameworks
    'LLM05': 0.6,  # Supply Chain Vulnerabilities
    'LLM06': 0.8,  # Sensitive Information Disclosure - high risk
    'LLM07': 0.5,  # Insecure Plugin Design
    'LLM08': 0.4,  # Excessive Agency - often FP in frameworks (tools/agents)
    'LLM09': 0.4,  # Overreliance
    'LLM10': 0.6,  # Model Theft - increased to avoid filtering real vulns
}


class FPReducer:
    """Ensemble false positive reducer for aisentry findings"""

    def __init__(
        self,
        use_ml: bool = True,
        use_llm: bool = False,
        llm_model: str = "claude-3-haiku-20240307",
        llm_threshold: float = 0.5,
        model_path: Optional[str] = None,
        weights: Optional[Dict[str, float]] = None,
    ):
        """
        Initialize the FP reducer.

        Args:
            use_ml: Whether to use ML classifier (requires scikit-learn)
            use_llm: Whether to use LLM verification (requires API key)
            llm_model: Which Claude model to use for verification
            llm_threshold: Only use LLM for findings above this heuristic score
            model_path: Path to saved ML model (optional)
            weights: Custom weights for ensemble {'heuristic': 0.4, 'ml': 0.3, 'llm': 0.3}
        """
        self.use_ml = use_ml and SKLEARN_AVAILABLE
        self.use_llm = use_llm and ANTHROPIC_AVAILABLE
        self.llm_model = llm_model
        self.llm_threshold = llm_threshold

        # Default weights
        self.weights = weights or {
            'heuristic': 0.4,
            'ml': 0.3,
            'llm': 0.3,
        }

        # ML components
        self.classifier = None
        self.vectorizer = None

        # Load saved model if provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

        # LLM client
        self.llm_client = None
        if self.use_llm:
            try:
                self.llm_client = anthropic.Anthropic()
            except Exception:
                self.use_llm = False

    def extract_features(self, finding: Finding) -> Dict[str, Any]:
        """Extract features from a finding for classification"""
        file_path_lower = finding.file_path.lower()
        desc_lower = finding.description.lower()
        code_lower = finding.code_snippet.lower() if finding.code_snippet else ""
        combined_text = f"{desc_lower} {code_lower}"

        features = {
            # File path features
            'is_test_file': any(re.search(p, file_path_lower) for p in LOW_RISK_PATHS[:4]),
            'is_example_file': any(re.search(p, file_path_lower) for p in [r'/examples?/', r'/demo/', r'/sample/']),
            'is_vendor_file': '/vendor/' in file_path_lower or '/node_modules/' in file_path_lower,
            'is_docs_file': '/docs/' in file_path_lower or file_path_lower.endswith('.md'),
            'path_depth': file_path_lower.count('/'),

            # FP pattern detection - original patterns
            'has_session_exec': any(re.search(p, combined_text) for p in FP_PATTERNS['session_exec']),
            'has_model_eval': any(re.search(p, combined_text) for p in FP_PATTERNS['model_eval']),
            'has_base64_image': any(re.search(p, combined_text) for p in FP_PATTERNS['base64_image']),
            'is_placeholder': any(re.search(p, combined_text, re.IGNORECASE) for p in FP_PATTERNS['placeholder']),
            'is_env_reference': any(re.search(p, combined_text) for p in FP_PATTERNS['env_reference']),

            # FP pattern detection - new patterns from real-world repos
            'has_async_run': any(re.search(p, combined_text) for p in FP_PATTERNS['async_run']),
            'has_super_run': any(re.search(p, combined_text) for p in FP_PATTERNS['super_run']),
            'has_server_runner': any(re.search(p, combined_text) for p in FP_PATTERNS['server_runner']),
            'has_framework_internal': any(re.search(p, combined_text) for p in FP_PATTERNS['framework_internal']),
            'has_executor_pool': any(re.search(p, combined_text) for p in FP_PATTERNS['executor_pool']),
            'has_build_tools': any(re.search(p, combined_text) for p in FP_PATTERNS['build_tools']),
            'has_callback_handler': any(re.search(p, combined_text) for p in FP_PATTERNS['callback_handler']),

            # Category features
            'category_code': finding.category.split(':')[0] if ':' in finding.category else finding.category,
            'category_risk': CATEGORY_RISK.get(finding.category.split(':')[0], 0.5),

            # Severity features
            'severity_score': {'CRITICAL': 1.0, 'HIGH': 0.75, 'MEDIUM': 0.5, 'LOW': 0.25}.get(finding.severity.upper(), 0.5),

            # Original confidence
            'static_confidence': finding.confidence,

            # Text features
            'description_length': len(finding.description),
            'has_code_snippet': bool(finding.code_snippet),
            'code_snippet_length': len(finding.code_snippet) if finding.code_snippet else 0,
        }

        return features

    def calculate_heuristic_score(self, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        Calculate heuristic-based TP probability.

        Returns:
            Tuple of (score, list of reasons for adjustment)
        """
        score = features['static_confidence'] * features['category_risk']
        reasons = []

        # CRITICAL severity findings skip file path penalties to ensure they're always shown
        is_critical = features['severity_score'] >= 1.0

        # Apply penalties for FP indicators - file path based (reduced for critical)
        if features['is_test_file']:
            if is_critical:
                score *= 0.7  # Reduced penalty for critical findings
                reasons.append("test file (-30%, reduced for critical)")
            else:
                score *= 0.3
                reasons.append("test file (-70%)")

        if features['is_example_file']:
            if is_critical:
                score *= 0.7
                reasons.append("example file (-30%, reduced for critical)")
            else:
                score *= 0.4
                reasons.append("example file (-60%)")

        if features['is_vendor_file']:
            score *= 0.2
            reasons.append("vendor file (-80%)")

        if features['is_docs_file']:
            if is_critical:
                score *= 0.7
                reasons.append("docs file (-30%, reduced for critical)")
            else:
                score *= 0.3
                reasons.append("docs file (-70%)")

        # Apply penalties for FP indicators - original patterns
        if features['has_session_exec']:
            score *= 0.1
            reasons.append("SQLAlchemy session.exec (-90%)")

        if features['has_model_eval']:
            score *= 0.1
            reasons.append("PyTorch model.eval (-90%)")

        if features['has_base64_image']:
            score *= 0.05
            reasons.append("base64 image (-95%)")

        if features['is_placeholder']:
            score *= 0.15
            reasons.append("placeholder value (-85%)")

        if features['is_env_reference']:
            score *= 0.5
            reasons.append("env variable reference (-50%)")

        # Apply penalties for FP indicators - new patterns from real-world repos
        if features.get('has_async_run'):
            score *= 0.15
            reasons.append("asyncio.run pattern (-85%)")

        if features.get('has_super_run'):
            score *= 0.1
            reasons.append("super().run inheritance (-90%)")

        if features.get('has_server_runner'):
            score *= 0.1
            reasons.append("server runner (uvicorn/gunicorn) (-90%)")

        if features.get('has_framework_internal'):
            score *= 0.2
            reasons.append("framework internal pattern (-80%)")

        if features.get('has_executor_pool'):
            score *= 0.15
            reasons.append("executor pool pattern (-85%)")

        if features.get('has_build_tools'):
            score *= 0.1
            reasons.append("build tool subprocess (-90%)")

        if features.get('has_callback_handler'):
            score *= 0.3
            reasons.append("callback handler pattern (-70%)")

        # Boost for high severity with code context
        if features['severity_score'] >= 0.75 and features['has_code_snippet']:
            score *= 1.2
            reasons.append("high severity with context (+20%)")

        return min(1.0, max(0.0, score)), reasons

    def calculate_ml_score(self, features: Dict[str, Any]) -> Optional[float]:
        """Calculate ML classifier score"""
        if not self.classifier or not self.vectorizer:
            return None

        try:
            # Prepare features for vectorizer (remove non-numeric category_code)
            ml_features = {k: v for k, v in features.items() if k != 'category_code'}
            X = self.vectorizer.transform([ml_features])
            proba = self.classifier.predict_proba(X)[0]
            # Return probability of being a true positive (class 1)
            return proba[1] if len(proba) > 1 else proba[0]
        except Exception:
            return None

    def calculate_llm_score(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """Use LLM to verify if finding is a true positive"""
        if not self.llm_client:
            return None

        try:
            code_context = finding.code_snippet or "No code snippet available"

            prompt = f"""Analyze this security finding and determine if it's a TRUE vulnerability or FALSE POSITIVE.

Finding Category: {finding.category}
Severity: {finding.severity}
Description: {finding.description}
File: {finding.file_path}

Code context:
```
{code_context[:2000]}
```

Consider:
1. Is this a real security risk or a safe API usage pattern?
2. Is this test/example code or production code?
3. Is the flagged value a placeholder or real credential?
4. Could this be a framework method with a similar name to a dangerous function?

Respond with ONLY a JSON object (no other text):
{{"is_tp": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""

            response = self.llm_client.messages.create(
                model=self.llm_model,
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}]
            )

            result_text = response.content[0].text.strip()
            # Extract JSON from response
            json_match = re.search(r'\{[^}]+\}', result_text)
            if json_match:
                result = json.loads(json_match.group())
                score = result['confidence'] if result.get('is_tp') else (1 - result['confidence'])
                return {
                    'score': score,
                    'is_tp': result.get('is_tp', False),
                    'reason': result.get('reason', 'No reason provided'),
                }
            return None
        except Exception:
            return None

    def score_finding(self, finding: Finding) -> Dict[str, Any]:
        """
        Score a single finding using ensemble approach.

        Returns:
            Dict with tp_probability, recommendation, and detailed scores
        """
        features = self.extract_features(finding)
        scores = {}
        reasons = []

        # 1. Heuristic score (always calculated)
        heuristic_score, heuristic_reasons = self.calculate_heuristic_score(features)
        scores['heuristic'] = heuristic_score
        reasons.extend(heuristic_reasons)

        # 2. ML classifier score (if available)
        if self.use_ml:
            ml_score = self.calculate_ml_score(features)
            if ml_score is not None:
                scores['ml'] = ml_score

        # 3. LLM verification (only for promising findings to save costs)
        if self.use_llm and heuristic_score >= self.llm_threshold:
            if finding.severity.upper() in ['HIGH', 'CRITICAL']:
                llm_result = self.calculate_llm_score(finding)
                if llm_result:
                    scores['llm'] = llm_result['score']
                    reasons.append(f"LLM: {llm_result['reason']}")

        # Calculate weighted ensemble score
        total_weight = 0
        weighted_sum = 0

        for method, score in scores.items():
            weight = self.weights.get(method, 0.33)
            weighted_sum += score * weight
            total_weight += weight

        final_score = weighted_sum / total_weight if total_weight > 0 else heuristic_score

        return {
            'finding_id': finding.id,
            'tp_probability': round(final_score, 3),
            'recommendation': 'KEEP' if final_score >= 0.4 else 'FILTER',
            'scores': scores,
            'reasons': reasons,
            'features': features,
        }

    def filter_findings(
        self,
        findings: List[Finding],
        threshold: float = 0.4,
        return_scores: bool = False,
    ):
        """
        Filter findings based on ensemble scoring.

        Args:
            findings: List of findings to filter
            threshold: Minimum TP probability to keep (default 0.4)
            return_scores: Whether to return detailed scores

        Returns:
            Filtered list of findings (and optionally scores)
        """
        results = []
        filtered_findings = []

        for finding in findings:
            score_result = self.score_finding(finding)
            results.append(score_result)

            if score_result['tp_probability'] >= threshold:
                filtered_findings.append(finding)

        if return_scores:
            return filtered_findings, results
        return filtered_findings

    def train(self, labeled_findings: List[Dict[str, Any]], save_path: Optional[str] = None):
        """
        Train the ML classifier on labeled findings.

        Args:
            labeled_findings: List of dicts with finding data + 'is_true_positive' label
            save_path: Optional path to save trained model
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML training")

        # Convert to Finding objects and extract features
        X = []
        y = []

        for item in labeled_findings:
            finding = Finding(
                id=item.get('id', ''),
                category=item.get('category', ''),
                severity=item.get('severity', 'MEDIUM'),
                confidence=item.get('confidence', 0.5),
                description=item.get('description', ''),
                file_path=item.get('file_path', ''),
                code_snippet=item.get('code_snippet', ''),
            )
            features = self.extract_features(finding)
            # Remove non-numeric features
            features = {k: v for k, v in features.items() if k != 'category_code'}
            X.append(features)
            y.append(1 if item.get('is_true_positive') else 0)

        # Vectorize and train
        self.vectorizer = DictVectorizer()
        X_vec = self.vectorizer.fit_transform(X)

        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            class_weight='balanced',  # Handle imbalanced data
        )
        self.classifier.fit(X_vec, y)

        # Save model if path provided
        if save_path:
            self.save_model(save_path)

        return self

    def save_model(self, path: str):
        """Save trained model to disk"""
        model_data = {
            'classifier': self.classifier,
            'vectorizer': self.vectorizer,
        }
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, path: str):
        """Load trained model from disk"""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            self.classifier = model_data['classifier']
            self.vectorizer = model_data['vectorizer']
        except ModuleNotFoundError:
            # sklearn not installed - can't unpickle the model
            self.use_ml = False
            self.classifier = None
            self.vectorizer = None

    def get_stats(self, findings: List[Finding], threshold: float = 0.4) -> Dict[str, Any]:
        """Get filtering statistics for a set of findings"""
        filtered, scores = self.filter_findings(findings, threshold, return_scores=True)

        kept = [s for s in scores if s['recommendation'] == 'KEEP']
        filtered_out = [s for s in scores if s['recommendation'] == 'FILTER']

        # Reason breakdown
        reason_counts = {}
        for s in filtered_out:
            for reason in s['reasons']:
                reason_key = reason.split(' (')[0]  # Remove percentage
                reason_counts[reason_key] = reason_counts.get(reason_key, 0) + 1

        return {
            'total': len(findings),
            'kept': len(kept),
            'filtered': len(filtered_out),
            'reduction_pct': round(100 * len(filtered_out) / len(findings), 1) if findings else 0,
            'avg_tp_probability': round(sum(s['tp_probability'] for s in scores) / len(scores), 3) if scores else 0,
            'filter_reasons': dict(sorted(reason_counts.items(), key=lambda x: -x[1])),
        }


def reduce_fps(scan_results: Dict[str, Any], threshold: float = 0.4, use_llm: bool = False) -> Dict[str, Any]:
    """
    Reduce false positives in scan results.

    Args:
        scan_results: Raw aisentry scan output
        threshold: Minimum TP probability to keep
        use_llm: Whether to use LLM verification for high-severity findings

    Returns:
        Modified scan results with filtered findings
    """
    reducer = FPReducer(use_ml=False, use_llm=use_llm)

    # Convert raw findings to Finding objects
    findings = []
    for f in scan_results.get('findings', []):
        findings.append(Finding(
            id=f.get('id', ''),
            category=f.get('category', ''),
            severity=f.get('severity', 'MEDIUM'),
            confidence=f.get('confidence', 0.5),
            description=f.get('description', ''),
            file_path=f.get('file_path', ''),
            line_number=f.get('line_number', 0),
            code_snippet=f.get('code_snippet', ''),
        ))

    # Filter and get stats
    filtered, scores = reducer.filter_findings(findings, threshold, return_scores=True)
    stats = reducer.get_stats(findings, threshold)

    # Update scan results
    filtered_ids = {f.id for f in filtered}
    scan_results['findings'] = [f for f in scan_results.get('findings', []) if f.get('id') in filtered_ids]
    scan_results['fp_reduction'] = stats

    return scan_results
