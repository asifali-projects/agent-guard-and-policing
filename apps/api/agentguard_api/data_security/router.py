"""Data security endpoints — /v1/data-security (PRD §27)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..dlp.detectors import DETECTORS, NEVER_EXFIL
from ..dlp.service import DEFAULT_ACTION, scan_payload
from ..models import DataClassificationRule, DataPolicy
from ..models.enums import DataClassification, DlpAction

router = APIRouter(prefix="/v1/data-security", tags=["data-security"])

ReadDep = Annotated[Principal, Depends(require_permission("data.read"))]
ManageDep = Annotated[Principal, Depends(require_permission("data.manage"))]


# --- scan ---------------------------------------------------------------


class ScanIn(BaseModel):
    payload: dict | None = None
    text: str | None = None

    @model_validator(mode="after")
    def _one(self) -> ScanIn:
        if not self.payload and not self.text:
            raise ValueError("provide 'payload' or 'text'")
        return self


class ScanFinding(BaseModel):
    path: str
    detector: str
    classification: DataClassification
    sample: str


class ScanOut(BaseModel):
    classification: DataClassification | None
    action: DlpAction
    findings: list[ScanFinding]
    redaction_paths: list[str]


@router.post("/scan", response_model=ScanOut)
async def scan(body: ScanIn, db: DbSession, principal: ReadDep) -> ScanOut:
    payload = body.payload if body.payload is not None else {"text": body.text}
    result = await scan_payload(db, principal.organization_id, payload)
    return ScanOut(
        classification=result.classification,
        action=result.action,
        findings=[
            ScanFinding(
                path=f.path, detector=f.detector, classification=f.classification, sample=f.sample
            )
            for f in result.findings
        ],
        redaction_paths=result.redaction_paths,
    )


@router.get("/detectors")
async def list_detectors(principal: ReadDep) -> dict:
    return {
        "detectors": sorted(DETECTORS),
        "never_exfil": sorted(NEVER_EXFIL),
        "default_actions": {k.value: v.value for k, v in DEFAULT_ACTION.items()},
    }


# --- classifications ---------------------------------------------------


class ClassificationIn(BaseModel):
    label: DataClassification
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    detectors: list[str] = Field(default_factory=list)


class ClassificationOut(ClassificationIn):
    id: uuid.UUID


@router.get("/classifications", response_model=list[ClassificationOut])
async def list_classifications(db: DbSession, principal: ReadDep) -> list[ClassificationOut]:
    rows = (
        await db.scalars(
            select(DataClassificationRule).where(
                DataClassificationRule.organization_id == principal.organization_id
            )
        )
    ).all()
    return [
        ClassificationOut(
            id=r.id, label=r.label, name=r.name, description=r.description, detectors=r.detectors
        )
        for r in rows
    ]


@router.post(
    "/classifications", response_model=ClassificationOut, status_code=status.HTTP_201_CREATED
)
async def create_classification(
    body: ClassificationIn, db: DbSession, principal: ManageDep
) -> ClassificationOut:
    dup = await db.scalar(
        select(DataClassificationRule.id).where(
            DataClassificationRule.organization_id == principal.organization_id,
            DataClassificationRule.label == body.label,
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "classification already defined")
    row = DataClassificationRule(
        organization_id=principal.organization_id,
        label=body.label,
        name=body.name,
        description=body.description,
        detectors=body.detectors,
    )
    db.add(row)
    await db.flush()
    return ClassificationOut(
        id=row.id,
        label=row.label,
        name=row.name,
        description=row.description,
        detectors=row.detectors,
    )


# --- data policies ---------------------------------------------------


class DataPolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    classification: DataClassification
    action: DlpAction = DlpAction.redact
    enabled: bool = True
    applies_to: dict = Field(default_factory=dict)


class DataPolicyPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    action: DlpAction | None = None
    enabled: bool | None = None
    applies_to: dict | None = None


class DataPolicyOut(DataPolicyIn):
    id: uuid.UUID


@router.get("/policies", response_model=list[DataPolicyOut])
async def list_policies(db: DbSession, principal: ReadDep) -> list[DataPolicyOut]:
    rows = (
        await db.scalars(
            select(DataPolicy).where(DataPolicy.organization_id == principal.organization_id)
        )
    ).all()
    return [
        DataPolicyOut(
            id=r.id,
            name=r.name,
            classification=r.classification,
            action=r.action,
            enabled=r.enabled,
            applies_to=r.applies_to,
        )
        for r in rows
    ]


@router.post("/policies", response_model=DataPolicyOut, status_code=status.HTTP_201_CREATED)
async def create_data_policy(
    body: DataPolicyIn, db: DbSession, principal: ManageDep
) -> DataPolicyOut:
    dup = await db.scalar(
        select(DataPolicy.id).where(
            DataPolicy.organization_id == principal.organization_id, DataPolicy.name == body.name
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "data policy name already used")
    row = DataPolicy(
        organization_id=principal.organization_id,
        name=body.name,
        classification=body.classification,
        action=body.action,
        enabled=body.enabled,
        applies_to=body.applies_to,
    )
    db.add(row)
    await db.flush()
    return DataPolicyOut(
        id=row.id,
        name=row.name,
        classification=row.classification,
        action=row.action,
        enabled=row.enabled,
        applies_to=row.applies_to,
    )


@router.patch("/policies/{policy_id}", response_model=DataPolicyOut)
async def update_data_policy(
    policy_id: uuid.UUID, body: DataPolicyPatch, db: DbSession, principal: ManageDep
) -> DataPolicyOut:
    row = await db.get(DataPolicy, policy_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "data policy not found")
    for f, v in body.model_dump(exclude_none=True).items():
        setattr(row, f, v)
    await db.flush()
    return DataPolicyOut(
        id=row.id,
        name=row.name,
        classification=row.classification,
        action=row.action,
        enabled=row.enabled,
        applies_to=row.applies_to,
    )


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_data_policy(policy_id: uuid.UUID, db: DbSession, principal: ManageDep) -> Response:
    row = await db.get(DataPolicy, policy_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "data policy not found")
    await db.delete(row)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
