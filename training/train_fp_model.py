#!/usr/bin/env python3
"""
Train the FP reducer ML model using labeled training data.

Usage:
    python train_fp_model.py

Output:
    training/fp_model.pkl - Trained model file
"""

import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aisentry.fp_reducer import FPReducer


def main():
    training_data_path = Path(__file__).parent / "fp_reducer_training_data.json"
    model_output_path = Path(__file__).parent / "fp_model.pkl"

    print(f"Loading training data from {training_data_path}")

    with open(training_data_path) as f:
        labeled_findings = json.load(f)

    print(f"Loaded {len(labeled_findings)} labeled findings")

    # Count TPs and FPs
    tp_count = sum(1 for f in labeled_findings if f.get("is_true_positive"))
    fp_count = len(labeled_findings) - tp_count
    print(f"  True Positives: {tp_count}")
    print(f"  False Positives: {fp_count}")

    # Initialize reducer and train
    print("\nTraining ML classifier...")
    reducer = FPReducer(use_ml=True, use_llm=False)

    try:
        reducer.train(labeled_findings, save_path=str(model_output_path))
        print(f"\nModel saved to {model_output_path}")

        # Test the model
        print("\nTesting model on training data...")
        correct = 0
        for finding in labeled_findings:
            from aisentry.fp_reducer import Finding

            f = Finding(
                id=finding.get("id", ""),
                category=finding.get("category", ""),
                severity=finding.get("severity", "MEDIUM"),
                confidence=finding.get("confidence", 0.5),
                description=finding.get("description", ""),
                file_path=finding.get("file_path", ""),
                code_snippet=finding.get("code_snippet", ""),
            )

            result = reducer.score_finding(f)
            predicted_tp = result["tp_probability"] >= 0.5
            actual_tp = finding.get("is_true_positive", False)

            if predicted_tp == actual_tp:
                correct += 1

        accuracy = correct / len(labeled_findings) * 100
        print(f"Training accuracy: {accuracy:.1f}%")

        # Feature importance
        if reducer.classifier and hasattr(reducer.classifier, "feature_importances_"):
            print("\nTop feature importances:")
            feature_names = reducer.vectorizer.get_feature_names_out()
            importances = reducer.classifier.feature_importances_
            sorted_idx = importances.argsort()[::-1][:10]
            for idx in sorted_idx:
                print(f"  {feature_names[idx]}: {importances[idx]:.3f}")

    except ImportError as e:
        print(f"\nError: {e}")
        print("Install scikit-learn to train the ML model:")
        print("  pip install scikit-learn")
        sys.exit(1)


if __name__ == "__main__":
    main()
