from typing import Any, AsyncGenerator, Type

import httpx
import pytest
import pytest_asyncio
from app.__main__ import main
from app.views import AppView
from client.config import DefaultsConfig
from client.requests import BaseRequests, UserRequests

from .conftest import PytestClientConfig


class BaseTestViews:
    T: Type[BaseRequests]

    @pytest_asyncio.fixture(scope="class")
    async def req(
        self,
        client_config: PytestClientConfig,
        async_client: httpx.AsyncClient,
    ):
        return self.T(client_config, async_client)  # type: ignore


@pytest.fixture(scope="session")
def defaults(client_config) -> DefaultsConfig:
    return client_config.defaults


class TestUserViews(BaseTestViews):
    T = UserRequests

    @pytest.mark.asyncio
    async def test_get_user(self, defaults: DefaultsConfig, req: UserRequests):
        result = await req.read(defaults.uuid_user)
        assert print(result.json())
