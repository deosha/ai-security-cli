"""
ONNX Export for Prompt Injection Classifier.

Exports trained LightGBM models to ONNX format for fast, portable inference.
The exported model can be used without requiring LightGBM or scikit-learn at runtime.

Usage:
    from aisentry.ml.training.export_onnx import export_to_onnx

    export_to_onnx(
        vulnerability_clf=trained_vuln_model,
        attack_type_clf=trained_attack_model,
        feature_names=feature_names,
        output_path='prompt_injection_v1.onnx'
    )
"""

import logging
from pathlib import Path
from typing import List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Optional ONNX dependencies
try:
    import onnx
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    ONNX_EXPORT_AVAILABLE = True
except ImportError:
    ONNX_EXPORT_AVAILABLE = False
    logger.warning(
        "ONNX export dependencies not available. "
        "Install with: pip install onnx onnxmltools skl2onnx"
    )


def export_to_onnx(
    vulnerability_clf,
    attack_type_clf,
    feature_names: List[str],
    output_path: str,
    model_name: str = "prompt_injection_classifier",
) -> None:
    """
    Export trained classifiers to ONNX format.

    Creates a combined model that outputs both vulnerability probability
    and attack vector classification.

    Args:
        vulnerability_clf: Trained vulnerability classifier (LGBMClassifier)
        attack_type_clf: Trained attack type classifier (LGBMClassifier)
        feature_names: List of feature names
        output_path: Path for output ONNX file
        model_name: Name for the ONNX model
    """
    if not ONNX_EXPORT_AVAILABLE:
        raise ImportError(
            "ONNX export requires: onnx, onnxmltools, skl2onnx. "
            "Install with: pip install onnx onnxmltools skl2onnx"
        )

    n_features = len(feature_names)
    initial_type = [('features', FloatTensorType([None, n_features]))]

    # Export vulnerability classifier
    logger.info("Converting vulnerability classifier to ONNX...")
    vuln_onnx = convert_lightgbm(
        vulnerability_clf,
        initial_types=initial_type,
        name=f"{model_name}_vulnerability",
        target_opset=12,
    )

    # Export attack type classifier
    logger.info("Converting attack type classifier to ONNX...")
    attack_onnx = convert_lightgbm(
        attack_type_clf,
        initial_types=initial_type,
        name=f"{model_name}_attack_type",
        target_opset=12,
    )

    # Save vulnerability model (primary model)
    output_path = Path(output_path)
    vuln_path = output_path.with_suffix('.vuln.onnx')
    attack_path = output_path.with_suffix('.attack.onnx')

    onnx.save(vuln_onnx, str(vuln_path))
    onnx.save(attack_onnx, str(attack_path))

    logger.info(f"Saved vulnerability model to {vuln_path}")
    logger.info(f"Saved attack type model to {attack_path}")

    # Also save combined metadata
    _save_model_metadata(
        output_path=str(output_path.with_suffix('.meta.json')),
        feature_names=feature_names,
        vuln_model_path=str(vuln_path),
        attack_model_path=str(attack_path),
    )


def _save_model_metadata(
    output_path: str,
    feature_names: List[str],
    vuln_model_path: str,
    attack_model_path: str,
) -> None:
    """Save model metadata for inference."""
    import json

    metadata = {
        'version': '1.0',
        'feature_names': feature_names,
        'n_features': len(feature_names),
        'models': {
            'vulnerability': vuln_model_path,
            'attack_type': attack_model_path,
        },
        'attack_labels': {
            '0': 'none',
            '1': 'direct',
            '2': 'indirect',
            '3': 'stored',
        },
        'description': 'Prompt injection detection classifier for Python code',
    }

    with open(output_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved model metadata to {output_path}")


def export_to_pickle(
    vulnerability_clf,
    attack_type_clf,
    feature_names: List[str],
    output_path: str,
) -> None:
    """
    Export models to pickle format (fallback when ONNX not available).

    Args:
        vulnerability_clf: Trained vulnerability classifier
        attack_type_clf: Trained attack type classifier
        feature_names: List of feature names
        output_path: Path for output pickle file
    """
    import pickle

    model_data = {
        'version': '1.0',
        'vulnerability_clf': vulnerability_clf,
        'attack_type_clf': attack_type_clf,
        'feature_names': feature_names,
        'attack_labels': {
            0: 'none',
            1: 'direct',
            2: 'indirect',
            3: 'stored',
        },
    }

    with open(output_path, 'wb') as f:
        pickle.dump(model_data, f)

    logger.info(f"Saved pickle model to {output_path}")


def validate_onnx_model(model_path: str, test_features: Optional[np.ndarray] = None) -> bool:
    """
    Validate an exported ONNX model.

    Args:
        model_path: Path to ONNX model file
        test_features: Optional test features for inference validation

    Returns:
        True if model is valid
    """
    if not ONNX_EXPORT_AVAILABLE:
        logger.warning("Cannot validate ONNX model - dependencies not available")
        return False

    try:
        model = onnx.load(model_path)
        onnx.checker.check_model(model)
        logger.info(f"ONNX model {model_path} is valid")

        # Test inference if features provided
        if test_features is not None:
            import onnxruntime as ort

            session = ort.InferenceSession(model_path)
            input_name = session.get_inputs()[0].name

            # Run inference
            result = session.run(None, {input_name: test_features.astype(np.float32)})
            logger.info(f"Test inference successful, output shape: {result[0].shape}")

        return True

    except Exception as e:
        logger.error(f"ONNX model validation failed: {e}")
        return False
