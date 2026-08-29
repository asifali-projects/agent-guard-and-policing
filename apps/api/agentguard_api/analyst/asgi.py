"""Standalone ASGI app for the `services/ai-analyst` deployment (PRD §35, §68).

Serves only the analyst surface, reusing the same models, DB, and engine as the
main API. Run with::

    uvicorn agentguard_api.analyst.asgi:app
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .. import __version__, cache, db
from ..config import get_settings
from ..logging import configure_logging, get_logger
from ..routers import health
from .router import router as analyst_router

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("ai-analyst.startup", version=__version__, engine_model=settings.analyst_model)
    yield
    await db.dispose()
    await cache.close()


app = FastAPI(
    title="AgentGuard AI Security Analyst",
    version=__version__,
    summary="Read-only natural-language Q&A over the AgentGuard control plane",
    lifespan=lifespan,
)
app.include_router(health.router)
app.include_router(analyst_router)
