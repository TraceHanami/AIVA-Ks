"""
Synthetic training data generator for the intent-prediction baseline.

Generates feature vectors shaped exactly like what
ai/feature_extraction/extractor.py + ai/graph_engine risk propagation
would produce for a given (graph, technique_matches) pair, labeled with
the ground-truth intent class used to synthesize them.

This is NOT a substitute for real labeled telemetry (see
research/DATASET_METHODOLOGY.md for the real-data plan) — it exists so
the training pipeline, feature schema, and evaluation code can be built
and verified end-to-end before real data collection is complete. This is
standard practice: prove the pipeline on synthetic data with known
ground truth, then swap the data source.
"""
from __future__ import annotations

import numpy as np

INTENT_CLASSES = [
    "Benign",
    "CredentialTheft",
    "Ransomware",
    "Exfiltration",
    "Persistence",
    "PrivilegeEscalation",
    "LateralMovement",
]

FEATURE_NAMES = [
    "max_node_risk",
    "mean_node_risk",
    "injects_edge_count",
    "rwx_mprotect_count",
    "credential_file_access_count",
    "file_write_bytes_rate",
    "distinct_outbound_targets",
    "process_lifespan_s",
    "syscall_rate_overall",
    "child_process_count",
]


def _rand_base(rng, lo=0.0, hi=0.2, size=None):
    return rng.uniform(lo, hi, size=size)


def generate_sample(rng: np.random.Generator, label: str) -> np.ndarray:
    """
    Each label has a distinct feature signature with realistic noise —
    this is what makes the classification task non-trivial rather than
    a lookup table, while still being learnable.
    """
    f = dict(zip(FEATURE_NAMES, _rand_base(rng, 0.0, 0.15, size=len(FEATURE_NAMES))))

    if label == "Benign":
        pass  # stays at low baseline noise

    elif label == "CredentialTheft":
        f["credential_file_access_count"] = rng.uniform(1, 5)
        f["injects_edge_count"] = rng.uniform(0, 2)
        f["max_node_risk"] = rng.uniform(0.5, 0.9)
        f["mean_node_risk"] = rng.uniform(0.2, 0.5)

    elif label == "Ransomware":
        f["file_write_bytes_rate"] = rng.uniform(5000, 50000)
        f["max_node_risk"] = rng.uniform(0.6, 0.95)
        f["mean_node_risk"] = rng.uniform(0.3, 0.6)
        f["child_process_count"] = rng.uniform(0, 3)

    elif label == "Exfiltration":
        f["distinct_outbound_targets"] = rng.uniform(3, 15)
        f["file_write_bytes_rate"] = rng.uniform(1000, 10000)
        f["max_node_risk"] = rng.uniform(0.5, 0.85)

    elif label == "Persistence":
        f["child_process_count"] = rng.uniform(2, 6)
        f["process_lifespan_s"] = rng.uniform(3600, 86400)
        f["max_node_risk"] = rng.uniform(0.3, 0.6)

    elif label == "PrivilegeEscalation":
        f["injects_edge_count"] = rng.uniform(1, 4)
        f["rwx_mprotect_count"] = rng.uniform(1, 3)
        f["max_node_risk"] = rng.uniform(0.6, 0.95)

    elif label == "LateralMovement":
        f["distinct_outbound_targets"] = rng.uniform(2, 8)
        f["child_process_count"] = rng.uniform(1, 4)
        f["syscall_rate_overall"] = rng.uniform(5, 20)
        f["max_node_risk"] = rng.uniform(0.4, 0.75)

    return np.array([f[name] for name in FEATURE_NAMES])


def generate_dataset(n_per_class: int = 300, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    X, y = [], []
    for label in INTENT_CLASSES:
        for _ in range(n_per_class):
            X.append(generate_sample(rng, label))
            y.append(label)
    return np.array(X), np.array(y)
