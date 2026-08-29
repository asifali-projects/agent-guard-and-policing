"""Data-loss prevention — classification + detectors + policy resolution (PRD §27).

`detectors` is pure (regex scanning of strings). `service` walks a payload,
classifies it, and resolves the configured action for the organization.
"""

from .detectors import DETECTORS, Finding, scan_text
from .service import DlpResult, scan_payload

__all__ = ["DETECTORS", "DlpResult", "Finding", "scan_payload", "scan_text"]
