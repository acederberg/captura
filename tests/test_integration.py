# =========================================================================== #
import asyncio
import secrets

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

# --------------------------------------------------------------------------- #
from app.auth import Auth
from app.schemas import mwargs
from client import Requests
from client.config import ProfileConfig
from client.handlers import AssertionHandler, ConsoleHandler
from client.requests.base import ContextData
from client.requests.users import UserRequests
from dummy import DummyProvider
from tests.config import PytestClientConfig


@pytest_asyncio.fixture
async def requests(app: FastAPI | None, client_config: PytestClientConfig, auth: Auth):
    """Requests client with built in assertions."""

    # NOTE: Somehow create a token client
    uuid = "000-000-000"
    client_config = client_config.model_copy()
    client_config.profiles.update(
        admin=mwargs(
            ProfileConfig,
            uuid_user=uuid,
            token=auth.encode(dict(uuid=uuid, permissions=["tier:admin"])),
        )
    )
    client_config.use.profile = "admin"

    async with httpx.AsyncClient(app=app) as client:
        requests = Requests(
            ContextData(
                openapi=False,
                config=client_config,
                console_handler=ConsoleHandler(client_config),
            ),
            client,
            handler=AssertionHandler(client_config),
        )

        yield requests


@pytest.mark.asyncio
async def test_from_nothing(requests: Requests):
    user = await requests.users.create(
        name="test_from_nothing",
        description="test_from_nothing",
        email=f"test{secrets.token_urlsafe()}@example.com",
    )
    assert print(user)
