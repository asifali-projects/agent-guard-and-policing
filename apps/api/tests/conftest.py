import os

os.environ.setdefault("AGENTGUARD_ENV", "test")

import pytest
from httpx import ASGITransport, AsyncClient

from agentguard_api.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
