"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__, cache, db
from .apikeys.router import router as apikeys_router
from .auth.router import router as auth_router
from .config import get_settings
from .logging import configure_logging, get_logger
from .organizations.router import router as organizations_router
from .routers import health

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("api.startup", environment=settings.environment, version=__version__)
    yield
    await db.dispose()
    await cache.close()
    log.info("api.shutdown")


app = FastAPI(
    title="AgentGuard API",
    version=__version__,
    summary="Security control plane for AI agents",
    description=(
        "Control-plane and runtime API for AgentGuard. This is the Step 0 "
        "scaffold — only health probes are implemented so far."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.include_router(health.router)
app.include_router(auth_router)
app.include_router(organizations_router)
app.include_router(apikeys_router)


@app.get("/", tags=["meta"], summary="Service banner")
async def root() -> dict[str, str]:
    return {
        "name": "AgentGuard API",
        "version": __version__,
        "environment": settings.environment,
        "docs": "/docs",
    }
