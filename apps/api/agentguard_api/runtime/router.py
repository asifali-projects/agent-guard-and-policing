"""Runtime API — /v1/runtime (PRD §42)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..auth.dependencies import DbSession, Principal, require_permission
from .schemas import RuntimeEvaluateRequest, RuntimeEvaluateResponse
from .service import evaluate_runtime

router = APIRouter(prefix="/v1/runtime", tags=["runtime"])


@router.post("/evaluate", response_model=RuntimeEvaluateResponse)
async def evaluate_endpoint(
    body: RuntimeEvaluateRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("runtime.evaluate"))],
) -> RuntimeEvaluateResponse:
    """Evaluate one attempted tool call. Deterministic; never calls an LLM."""
    return await evaluate_runtime(db, principal, body)
