"""
AIVA-KS Attack Intent Prediction — baseline model (Phase 8, stage 1).

Architecture doc calls for a Temporal GNN as the target architecture
(sequence-aware, operates directly on the behavioral graph). This module
implements the recommended STARTING point instead: a gradient-boosted
tree classifier over hand-engineered graph/feature-derived features.

Why start here rather than jumping straight to a GNN:
  - It needs no GPU, no graph batching infrastructure, and trains in
    seconds — so the training pipeline, evaluation harness, and model
    versioning/serving contract can all be built and tested NOW.
  - It gives a real accuracy baseline that the eventual GNN has to beat
    to justify its added complexity — standard ML practice.
  - The feature vector it consumes (FEATURE_NAMES in synthetic_data.py)
    is exactly what ai/feature_extraction + graph risk propagation
    already produce, so swapping in real telemetry later requires no
    interface change.

The GNN upgrade path is sketched in `gnn_model.py` (interface only).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from ai.intent_prediction.synthetic_data import FEATURE_NAMES, generate_dataset

MODEL_VERSION = "baseline-gbt-v0.1"


class IntentPredictor:
    def __init__(self):
        self.model = GradientBoostingClassifier(
            n_estimators=150, max_depth=3, learning_rate=0.1, random_state=42
        )
        self.label_encoder = LabelEncoder()
        self.is_fitted = False

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        y_enc = self.label_encoder.fit_transform(y)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )
        self.model.fit(X_train, y_train)
        self.is_fitted = True

        y_pred = self.model.predict(X_test)
        report = classification_report(
            y_test, y_pred, target_names=self.label_encoder.classes_,
            output_dict=True, zero_division=0,
        )
        cm = confusion_matrix(y_test, y_pred)
        return {"report": report, "confusion_matrix": cm.tolist(),
                "classes": list(self.label_encoder.classes_)}

    def predict(self, features: dict[str, float]) -> tuple[str, float]:
        """features: dict matching FEATURE_NAMES — as produced by feature_extraction."""
        if not self.is_fitted:
            raise RuntimeError("model not trained/loaded")
        x = np.array([[features.get(name, 0.0) for name in FEATURE_NAMES]])
        proba = self.model.predict_proba(x)[0]
        idx = np.argmax(proba)
        return self.label_encoder.classes_[idx], float(proba[idx])

    def feature_importances(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.model.feature_importances_.tolist()))

    def save(self, path: str):
        import joblib
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "label_encoder": self.label_encoder,
                     "version": MODEL_VERSION}, path)

    @classmethod
    def load(cls, path: str) -> "IntentPredictor":
        import joblib
        data = joblib.load(path)
        obj = cls()
        obj.model = data["model"]
        obj.label_encoder = data["label_encoder"]
        obj.is_fitted = True
        return obj


def main():
    print(f"Training {MODEL_VERSION} on synthetic dataset...")
    X, y = generate_dataset(n_per_class=300)
    predictor = IntentPredictor()
    results = predictor.train(X, y)

    print("\n=== Classification report (held-out test set) ===")
    for cls, metrics in results["report"].items():
        if isinstance(metrics, dict):
            print(f"  {cls:22s} precision={metrics['precision']:.2f} "
                  f"recall={metrics['recall']:.2f} f1={metrics['f1-score']:.2f} "
                  f"support={int(metrics['support'])}")
    print(f"\n  accuracy: {results['report']['accuracy']:.3f}")

    print("\n=== Feature importances ===")
    for name, imp in sorted(predictor.feature_importances().items(), key=lambda x: -x[1]):
        print(f"  {name:32s} {imp:.3f}")

    predictor.save("ai/intent_prediction/model_artifacts/baseline_gbt.joblib")
    print("\nModel saved to ai/intent_prediction/model_artifacts/baseline_gbt.joblib")

    # sanity-check inference on a hand-built "credential theft" feature vector
    sample = {
        "max_node_risk": 0.8, "mean_node_risk": 0.4, "injects_edge_count": 1,
        "rwx_mprotect_count": 1, "credential_file_access_count": 2,
        "file_write_bytes_rate": 100, "distinct_outbound_targets": 1,
        "process_lifespan_s": 30, "syscall_rate_overall": 3, "child_process_count": 1,
    }
    pred_class, confidence = predictor.predict(sample)
    print(f"\nSanity check inference: predicted={pred_class} confidence={confidence:.2f}")


if __name__ == "__main__":
    main()
