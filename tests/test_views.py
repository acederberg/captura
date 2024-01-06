import asyncio
import json
import secrets
import sys
from typing import Any, AsyncGenerator, Type

import httpx
import pytest
import pytest_asyncio
from app.__main__ import main
from app.auth import Auth
from app.models import User
from app.views import AppView
from client.config import DefaultsConfig
from client.requests import BaseRequests, UserRequests
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from .conftest import PytestClientConfig

DEFAULT_UUID: str = "00000000"
DEFAULT_TOKEN_PAYLOAD = dict(uuid=DEFAULT_UUID)


class BaseTestViews:
    T: Type[BaseRequests]

    @pytest_asyncio.fixture(params=[DEFAULT_TOKEN_PAYLOAD])
    async def client(
        self,
        client_config: PytestClientConfig,
        async_client: httpx.AsyncClient,
        auth: Auth,
        request,
    ):
        token = auth.encode(request.param or DEFAULT_TOKEN_PAYLOAD)
        return self.T(client_config, async_client, token=token)

    @pytest.fixture(scope="session", autouse=True)
    def invoke_loader(self, load_tables, setup_cleanup):
        ...


def check_status(
    response: httpx.Response, expect: int | None = None
) -> AssertionError | None:
    if expect is not None and response.status_code == expect:
        return None
    elif 200 <= response.status_code < 300:
        return None

    req_json = (req := response.request).read().decode()
    res_json = json.dumps(response.json(), indent=2)

    msg = f"`{req.method} {req.url}` "
    if req_json:
        msg += f"with body `{req_json}`"
    msg = (
        f"Unexpected status code `{response.status_code}` from {msg}. The "
        f"response included the following detail: {res_json}."
    )
    if auth := req.headers.get("authorization"):
        msg += f"Authorization: {auth}"

    return AssertionError(msg)


class TestUserViews(BaseTestViews):
    T = UserRequests

    @pytest.mark.asyncio
    async def test_get_user(self, client: UserRequests):
        "Test for the very limitted (at the moment) GET /users/{uuid}"
        # good is the default user, other is almost certain not to exist.
        good, bad = await asyncio.gather(
            *(client.read(uuid) for uuid in (DEFAULT_UUID, "foobarz"))
        )
        if err := check_status(good, 200):
            raise err
        elif err := check_status(bad, 204):
            raise err

        assert isinstance(result := good.json(), dict)
        assert result["uuid"] == DEFAULT_UUID

        assert bad.status_code == 204

    # TODO: Add a test that collaborators can see this users account.
    @pytest.mark.asyncio
    async def test_get_user_public(self, client: UserRequests):
        """Test GET /users/{uuid} for a private user.

        Eventually the queries should deal with 'deactivation' via API
        eventually.
        """
        response = await client.patch(DEFAULT_UUID, public=False)
        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 204):
            raise err

        response = await client.patch(DEFAULT_UUID, public=True)
        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 200):
            raise err
        result = response.json()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_patch_user(self, client: UserRequests):
        new_name = secrets.token_hex(4)
        good, bad = await asyncio.gather(
            *(client.patch(uuid, name=new_name) for uuid in (DEFAULT_UUID, "99999999"))
        )
        if err := check_status(good):
            raise err
        elif err := check_status(bad, 403):
            raise err

        updated = await client.read(DEFAULT_UUID)
        if err := check_status(updated):
            raise err

        assert isinstance(result := updated.json(), dict)
        assert result["uuid"] == DEFAULT_UUID
        assert result["name"] == new_name

    @pytest.mark.asyncio
    async def test_delete_user(self, client: UserRequests):
        res = await client.delete(DEFAULT_UUID)
        if err := check_status(res):
            raise err
