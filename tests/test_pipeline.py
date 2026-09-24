"""
Compatibility shim for demo scripts and legacy modules referencing tests.test_pipeline.
Exports synthetic telemetry datasets from chronos.research.demo_data.
"""
from chronos.research.demo_data import ATTACK_EVENTS, BENIGN_EVENTS, HOST

__all__ = ["ATTACK_EVENTS", "BENIGN_EVENTS", "HOST"]
