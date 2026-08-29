"""AI Red Team — a first-class module, not an add-on (PRD §18–22).

Target Agent -> Attack Planner -> Generator -> Sandbox -> Observation
             -> Evaluator -> Risk Classification -> Finding
"""

from .catalog import (
    TECHNIQUES,
    remediation_spec,
    technique_by_id,
    technique_by_name,
    techniques_for,
)
from .runner import run_assessment

__all__ = [
    "TECHNIQUES",
    "remediation_spec",
    "run_assessment",
    "technique_by_id",
    "technique_by_name",
    "techniques_for",
]
