"""Walk a payload, classify it, resolve the configured DLP action (PRD §27)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DataPolicy
from ..models.enums import DataClassification, DlpAction
from .detectors import NEVER_EXFIL, Finding, highest_classification, scan_text

# Applied when the organization has no matching DataPolicy row.
DEFAULT_ACTION: dict[DataClassification, DlpAction] = {
    DataClassification.public: DlpAction.allow,
    DataClassification.internal: DlpAction.allow,
    DataClassification.confidential: DlpAction.redact,
    DataClassification.restricted: DlpAction.block,
}
_ACTION_SEVERITY = {
    DlpAction.allow: 0,
    DlpAction.redact: 1,
    DlpAction.approval: 2,
    DlpAction.block: 3,
}


@dataclass
class PathFinding:
    path: str
    detector: str
    classification: DataClassification
    sample: str


@dataclass
class DlpResult:
    findings: list[PathFinding] = field(default_factory=list)
    classification: DataClassification | None = None
    action: DlpAction = DlpAction.allow
    redaction_paths: list[str] = field(default_factory=list)

    @property
    def has_never_exfil(self) -> bool:
        return any(f.detector in NEVER_EXFIL for f in self.findings)


def _walk(node: object, prefix: str) -> list[tuple[str, str, str]]:
    """Yield (path, key_hint, string_value) for every string leaf."""
    out: list[tuple[str, str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(_walk(v, f"{prefix}.{k}"))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(_walk(v, f"{prefix}[{i}]"))
    elif isinstance(node, str):
        key_hint = prefix.rsplit(".", 1)[-1].split("[", 1)[0]
        out.append((prefix, key_hint, node))
    return out


def scan_dict(parameters: dict, *, root: str = "parameters") -> list[PathFinding]:
    results: list[PathFinding] = []
    for path, key_hint, value in _walk(parameters, root):
        for f in scan_text(value, key_hint=key_hint):
            results.append(PathFinding(path, f.detector, f.classification, f.sample))
    return results


async def _resolve_action(
    session: AsyncSession,
    organization_id: uuid.UUID,
    classification: DataClassification,
    *,
    force_block: bool,
) -> DlpAction:
    if force_block:
        return DlpAction.block
    rows = (
        await session.scalars(
            select(DataPolicy).where(
                DataPolicy.organization_id == organization_id,
                DataPolicy.classification == classification,
                DataPolicy.enabled.is_(True),
            )
        )
    ).all()
    if rows:
        return max((r.action for r in rows), key=lambda a: _ACTION_SEVERITY[a])
    return DEFAULT_ACTION[classification]


async def scan_payload(
    session: AsyncSession, organization_id: uuid.UUID, parameters: dict
) -> DlpResult:
    path_findings = scan_dict(parameters or {})
    if not path_findings:
        return DlpResult()

    as_findings = [Finding(f.detector, f.classification, f.sample) for f in path_findings]
    classification = highest_classification(as_findings)
    assert classification is not None

    force_block = any(f.detector in NEVER_EXFIL for f in path_findings)
    action = await _resolve_action(
        session, organization_id, classification, force_block=force_block
    )
    redaction_paths: list[str] = []
    for f in path_findings:
        if f.path not in redaction_paths:
            redaction_paths.append(f.path)

    return DlpResult(
        findings=path_findings,
        classification=classification,
        action=action,
        redaction_paths=redaction_paths,
    )
