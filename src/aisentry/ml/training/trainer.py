"""
ML Training Pipeline for Prompt Injection Classifier.

Trains a LightGBM classifier on synthetic code samples to detect
prompt injection vulnerabilities and classify attack vectors.

Usage:
    from aisentry.ml.training import PromptInjectionTrainer

    trainer = PromptInjectionTrainer()
    trainer.load_data('training_data.jsonl')
    trainer.train()
    trainer.evaluate()
    trainer.export_onnx('prompt_injection_v1.onnx')
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from aisentry.ml.feature_extractor import FeatureExtractor
from aisentry.ml.training.synthetic_generator import (
    SyntheticDataGenerator,
    CodeSample,
    VulnerabilityLabel,
)

logger = logging.getLogger(__name__)

# Try to import ML libraries (optional dependencies)
LIGHTGBM_AVAILABLE = False
try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except (ImportError, OSError):
    # OSError can happen on macOS if libomp is missing
    logger.info("LightGBM not available, will use sklearn fallback")

try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )
    from sklearn.ensemble import GradientBoostingClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available. Install with: pip install scikit-learn")


@dataclass
class TrainingMetrics:
    """Metrics from model training and evaluation."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: Optional[float]
    confusion_matrix: np.ndarray
    classification_report: str
    cross_val_scores: Optional[np.ndarray] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'roc_auc': self.roc_auc,
            'confusion_matrix': self.confusion_matrix.tolist(),
            'cross_val_mean': float(np.mean(self.cross_val_scores)) if self.cross_val_scores is not None else None,
            'cross_val_std': float(np.std(self.cross_val_scores)) if self.cross_val_scores is not None else None,
        }


class PromptInjectionTrainer:
    """
    Train prompt injection detection models.

    Architecture:
    1. Binary classifier: vulnerable vs safe
    2. Multi-class classifier: attack vector type (direct, indirect, stored)

    Both models use the same 45-dimensional feature vector from AST analysis.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        random_state: int = 42,
    ):
        """
        Initialize trainer.

        Args:
            n_estimators: Number of boosting rounds
            max_depth: Maximum tree depth
            learning_rate: Boosting learning rate
            random_state: Random seed for reproducibility
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required for training. Install with: pip install scikit-learn")

        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.random_state = random_state

        self.feature_extractor = FeatureExtractor()

        # Choose classifier based on availability
        if LIGHTGBM_AVAILABLE:
            logger.info("Using LightGBM classifier")
            # Binary classifier (vulnerable vs safe)
            self.vulnerability_clf = LGBMClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=learning_rate,
                random_state=random_state,
                verbose=-1,
            )

            # Multi-class classifier (attack vector)
            self.attack_type_clf = LGBMClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=learning_rate,
                random_state=random_state,
                verbose=-1,
                objective='multiclass',
                num_class=4,  # direct, indirect, stored, none
            )
        else:
            logger.info("Using sklearn GradientBoostingClassifier (LightGBM not available)")
            # Binary classifier (vulnerable vs safe)
            self.vulnerability_clf = GradientBoostingClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=learning_rate,
                random_state=random_state,
            )

            # Multi-class classifier (attack vector)
            self.attack_type_clf = GradientBoostingClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=learning_rate,
                random_state=random_state,
            )

        # Training data
        self.X_train: Optional[np.ndarray] = None
        self.X_test: Optional[np.ndarray] = None
        self.y_vuln_train: Optional[np.ndarray] = None
        self.y_vuln_test: Optional[np.ndarray] = None
        self.y_attack_train: Optional[np.ndarray] = None
        self.y_attack_test: Optional[np.ndarray] = None

        # Feature names for interpretability
        self.feature_names: List[str] = []

        # Attack vector label mapping
        self.attack_label_map = {
            'safe': 0,
            'none': 0,
            'direct': 1,
            'indirect': 2,
            'stored': 3,
        }
        self.attack_label_inverse = {v: k for k, v in self.attack_label_map.items()}

    def generate_synthetic_data(
        self,
        num_samples: int = 5000,
        safe_ratio: float = 0.4,
        seed: Optional[int] = None,
    ) -> List[CodeSample]:
        """
        Generate synthetic training data.

        Args:
            num_samples: Total number of samples
            safe_ratio: Proportion of safe samples
            seed: Random seed

        Returns:
            List of CodeSample objects
        """
        generator = SyntheticDataGenerator(seed=seed or self.random_state)
        samples = generator.generate_dataset(
            num_samples=num_samples,
            safe_ratio=safe_ratio,
        )
        logger.info(f"Generated {len(samples)} synthetic samples")
        return samples

    def load_data(self, data_path: str) -> None:
        """
        Load training data from JSONL file.

        Args:
            data_path: Path to JSONL file with CodeSample data
        """
        samples = []
        with open(data_path, 'r') as f:
            for line in f:
                data = json.loads(line)
                samples.append(CodeSample(
                    code=data['code'],
                    label=VulnerabilityLabel(data['label']),
                    attack_vector=data['attack_vector'],
                    has_mitigation=data['has_mitigation'],
                    metadata=data.get('metadata', {}),
                ))

        logger.info(f"Loaded {len(samples)} samples from {data_path}")
        self._prepare_features(samples)

    def load_samples(self, samples: List[CodeSample]) -> None:
        """
        Load training data from CodeSample list.

        Args:
            samples: List of CodeSample objects
        """
        logger.info(f"Loading {len(samples)} samples")
        self._prepare_features(samples)

    def _prepare_features(self, samples: List[CodeSample]) -> None:
        """Extract features and prepare train/test split."""
        import tempfile
        from aisentry.parsers.python.ast_parser import PythonASTParser

        X = []
        y_vuln = []
        y_attack = []

        for sample in samples:
            # Parse code to extract features
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(sample.code)
                    f.flush()
                    parser = PythonASTParser(f.name)
                    parsed_data = parser.parse()

                if parsed_data.get('parsable', False):
                    features = self.feature_extractor.extract(parsed_data)
                    X.append(features.features)

                    # Binary label: vulnerable (1) or safe (0)
                    is_vulnerable = 1 if sample.label != VulnerabilityLabel.SAFE else 0
                    y_vuln.append(is_vulnerable)

                    # Attack vector label
                    attack_label = self.attack_label_map.get(sample.attack_vector, 0)
                    y_attack.append(attack_label)

                    # Store feature names (once)
                    if not self.feature_names:
                        self.feature_names = features.feature_names

            except Exception as e:
                logger.warning(f"Failed to parse sample: {e}")
                continue

        X = np.array(X, dtype=np.float32)
        y_vuln = np.array(y_vuln, dtype=np.int32)
        y_attack = np.array(y_attack, dtype=np.int32)

        # Train/test split
        (
            self.X_train, self.X_test,
            self.y_vuln_train, self.y_vuln_test,
            self.y_attack_train, self.y_attack_test
        ) = train_test_split(
            X, y_vuln, y_attack,
            test_size=0.2,
            random_state=self.random_state,
            stratify=y_vuln,
        )

        logger.info(f"Prepared {len(self.X_train)} training samples, {len(self.X_test)} test samples")
        logger.info(f"Vulnerable ratio: {np.mean(y_vuln):.2%}")

    def train(self, cross_validate: bool = True) -> Tuple[TrainingMetrics, TrainingMetrics]:
        """
        Train both classifiers.

        Args:
            cross_validate: Whether to run cross-validation

        Returns:
            Tuple of (vulnerability_metrics, attack_type_metrics)
        """
        if self.X_train is None:
            raise ValueError("No training data loaded. Call load_data() or load_samples() first.")

        logger.info("Training vulnerability classifier...")
        self.vulnerability_clf.fit(self.X_train, self.y_vuln_train)

        # Evaluate vulnerability classifier
        vuln_metrics = self._evaluate_classifier(
            self.vulnerability_clf,
            self.X_test,
            self.y_vuln_test,
            cross_validate=cross_validate,
            X_full=np.vstack([self.X_train, self.X_test]) if cross_validate else None,
            y_full=np.hstack([self.y_vuln_train, self.y_vuln_test]) if cross_validate else None,
        )
        logger.info(f"Vulnerability classifier - F1: {vuln_metrics.f1_score:.3f}, AUC: {vuln_metrics.roc_auc:.3f}")

        # Train attack type classifier on vulnerable samples only
        logger.info("Training attack type classifier...")
        vuln_mask_train = self.y_vuln_train == 1
        vuln_mask_test = self.y_vuln_test == 1

        if np.sum(vuln_mask_train) > 10:
            self.attack_type_clf.fit(
                self.X_train[vuln_mask_train],
                self.y_attack_train[vuln_mask_train]
            )

            attack_metrics = self._evaluate_classifier(
                self.attack_type_clf,
                self.X_test[vuln_mask_test],
                self.y_attack_test[vuln_mask_test],
                cross_validate=False,  # Smaller dataset, skip CV
            )
            logger.info(f"Attack type classifier - F1: {attack_metrics.f1_score:.3f}")
        else:
            logger.warning("Not enough vulnerable samples to train attack type classifier")
            attack_metrics = TrainingMetrics(
                accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
                roc_auc=None, confusion_matrix=np.array([]),
                classification_report="Insufficient data"
            )

        return vuln_metrics, attack_metrics

    def _evaluate_classifier(
        self,
        clf,
        X_test: np.ndarray,
        y_test: np.ndarray,
        cross_validate: bool = False,
        X_full: Optional[np.ndarray] = None,
        y_full: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        """Evaluate a classifier and return metrics."""
        if len(X_test) == 0:
            return TrainingMetrics(
                accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
                roc_auc=None, confusion_matrix=np.array([]),
                classification_report="No test data"
            )

        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)

        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted', zero_division=0
        )

        accuracy = np.mean(y_pred == y_test)

        # ROC AUC (binary or multi-class)
        try:
            if len(np.unique(y_test)) == 2:
                roc_auc = roc_auc_score(y_test, y_prob[:, 1])
            else:
                roc_auc = roc_auc_score(y_test, y_prob, multi_class='ovr', average='weighted')
        except ValueError:
            roc_auc = None

        # Cross-validation
        cv_scores = None
        if cross_validate and X_full is not None and y_full is not None:
            cv_scores = cross_val_score(clf, X_full, y_full, cv=5, scoring='f1_weighted')

        return TrainingMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test, y_pred),
            classification_report=classification_report(y_test, y_pred, zero_division=0),
            cross_val_scores=cv_scores,
        )

    def get_feature_importance(self, top_n: int = 10) -> Dict[str, float]:
        """
        Get top feature importances from vulnerability classifier.

        Args:
            top_n: Number of top features to return

        Returns:
            Dict mapping feature name to importance
        """
        if not hasattr(self.vulnerability_clf, 'feature_importances_'):
            return {}

        importances = self.vulnerability_clf.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]

        return {
            self.feature_names[i]: float(importances[i])
            for i in indices
        }

    def save_model(self, path: str) -> None:
        """
        Save trained models to disk.

        Args:
            path: Base path for model files
        """
        import pickle

        model_data = {
            'vulnerability_clf': self.vulnerability_clf,
            'attack_type_clf': self.attack_type_clf,
            'feature_names': self.feature_names,
            'attack_label_map': self.attack_label_map,
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Saved model to {path}")

    def load_model(self, path: str) -> None:
        """
        Load trained models from disk.

        Args:
            path: Path to saved model file
        """
        import pickle

        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.vulnerability_clf = model_data['vulnerability_clf']
        self.attack_type_clf = model_data['attack_type_clf']
        self.feature_names = model_data['feature_names']
        self.attack_label_map = model_data['attack_label_map']
        self.attack_label_inverse = {v: k for k, v in self.attack_label_map.items()}

        logger.info(f"Loaded model from {path}")

    def export_onnx(self, output_path: str) -> None:
        """
        Export models to ONNX format for fast inference.

        Args:
            output_path: Path for ONNX model file
        """
        from aisentry.ml.training.export_onnx import export_to_onnx

        export_to_onnx(
            vulnerability_clf=self.vulnerability_clf,
            attack_type_clf=self.attack_type_clf,
            feature_names=self.feature_names,
            output_path=output_path,
        )

        logger.info(f"Exported ONNX model to {output_path}")
