"""Data-residency regions — PRD §76.

Each region (US / EU / Middle East / APAC) is a fully isolated deployment: its
own control plane, data plane, and event store. An organization is pinned to one
home region at creation and its data never leaves. This deployment serves
exactly one region (``settings.region``); requests for an organization homed
elsewhere are refused with ``421 Misdirected Request`` and a pointer to the
correct regional endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel

from .config import get_settings
from .models.enums import Region

DISPLAY_NAMES: dict[Region, str] = {
    Region.us: "United States",
    Region.eu: "European Union",
    Region.me: "Middle East",
    Region.apac: "Asia-Pacific",
}


def current_region() -> Region:
    return Region(get_settings().region)


def catalog() -> list[dict]:
    """The advertised regions, for client-side routing (`GET /v1/regions`)."""
    current = get_settings().region
    rows: list[dict] = []
    for entry in get_settings().region_catalog:
        code = entry["code"]
        try:
            region = Region(code)
        except ValueError:
            continue
        rows.append(
            {
                "code": code,
                "name": entry["name"] or DISPLAY_NAMES.get(region, code.upper()),
                "api_url": entry["api_url"],
                "web_url": entry["web_url"] or None,
                "current": code == current,
            }
        )
    return rows


def endpoint_for(region: Region) -> dict | None:
    return next((r for r in catalog() if r["code"] == region.value), None)


def is_servable(region: Region) -> bool:
    return region.value == get_settings().region


def assert_servable(region: Region) -> None:
    """Raise 421 unless ``region`` is the one this deployment serves."""
    if is_servable(region):
        return
    target = endpoint_for(region)
    headers = {"X-AgentGuard-Region": region.value}
    if target and target.get("api_url"):
        headers["X-AgentGuard-Region-Url"] = target["api_url"]
    raise HTTPException(
        status.HTTP_421_MISDIRECTED_REQUEST,
        detail=(
            f"this organization's data resides in the '{region.value}' "
            f"({DISPLAY_NAMES.get(region, region.value)}) region; use that regional endpoint"
        ),
        headers=headers,
    )


# --- discovery endpoint --------------------------------------------------

router = APIRouter(prefix="/v1/regions", tags=["regions"])


class RegionOut(BaseModel):
    code: str
    name: str
    api_url: str
    web_url: str | None = None
    current: bool


class RegionsResponse(BaseModel):
    current: str
    regions: list[RegionOut]


@router.get("", response_model=RegionsResponse)
async def list_regions() -> RegionsResponse:
    """Public: where each region's data lives, so a client can route itself."""
    return RegionsResponse(
        current=get_settings().region,
        regions=[RegionOut(**row) for row in catalog()],
    )
