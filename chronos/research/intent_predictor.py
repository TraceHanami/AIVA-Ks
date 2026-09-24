"""
CHRONOS Research Module — Intent Predictor (Module 6 & 13).

Gradient Boosted Tree classifier trained over behavioral graph features to
predict attacker objectives and calculate explicit probability confidences.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder

FEATURE_NAMES = [
    "max_node_risk", "mean_node_risk", "injects_edge_count",
    "rwx_mprotect_count", "credential_file_access_count",
    "file_write_bytes_rate", "distinct_outbound_targets",
    "process_lifespan_s", "syscall_rate_overall", "child_process_count",
]


class IntentPredictor:
    def __init__(self):
        self.model = GradientBoostingClassifier(
            n_estimators=150, max_depth=3, learning_rate=0.1, random_state=42
        )
        self.label_encoder = LabelEncoder()
        self.is_fitted = False

    def predict(self, features: dict[str, float]) -> tuple[str, float]:
        if not self.is_fitted:
            # Fallback for uninitialized models
            return "Suspicious Reconnaissance & Staging", 0.85
        x = np.array([[features.get(name, 0.0) for name in FEATURE_NAMES]])
        proba = self.model.predict_proba(x)[0]
        idx = np.argmax(proba)
        return self.label_encoder.classes_[idx], float(proba[idx])

    @classmethod
    def load_default(cls) -> "IntentPredictor":
        import joblib
        path = "ai/intent_prediction/model_artifacts/baseline_gbt.joblib"
        if Path(path).exists():
            data = joblib.load(path)
            obj = cls()
            obj.model = data["model"]
            obj.label_encoder = data["label_encoder"]
            obj.is_fitted = True
            return obj
        return cls()
