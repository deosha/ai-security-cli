"""
Training Pipeline for Prompt Injection Classifier.

This module provides tools for:
- Loading and preprocessing datasets (HackAPrompt, Tensor Trust, etc.)
- Generating synthetic training data from prompt datasets
- Training the classifier model
- Exporting to ONNX format

Usage:
    from aisentry.ml.training import PromptInjectionTrainer, SyntheticDataGenerator

    # Generate training data
    generator = SyntheticDataGenerator(seed=42)
    samples = generator.generate_dataset(num_samples=5000)

    # Train model
    trainer = PromptInjectionTrainer()
    trainer.load_samples(samples)
    vuln_metrics, attack_metrics = trainer.train()

    # Export to ONNX
    trainer.export_onnx('prompt_injection_v1.onnx')
"""

from aisentry.ml.training.synthetic_generator import (
    SyntheticDataGenerator,
    CodeSample,
    VulnerabilityLabel,
)

# Import trainer and export (require sklearn, optionally lightgbm)
try:
    from aisentry.ml.training.trainer import PromptInjectionTrainer, TrainingMetrics
    from aisentry.ml.training.export_onnx import export_to_onnx, export_to_pickle
    _TRAINING_AVAILABLE = True
except ImportError:
    _TRAINING_AVAILABLE = False
    PromptInjectionTrainer = None
    TrainingMetrics = None
    export_to_onnx = None
    export_to_pickle = None

__all__ = [
    "SyntheticDataGenerator",
    "CodeSample",
    "VulnerabilityLabel",
    "PromptInjectionTrainer",
    "TrainingMetrics",
    "export_to_onnx",
    "export_to_pickle",
]
