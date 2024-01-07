import asyncio
import json
import secrets
import sys
from typing import Any, AsyncGenerator, Tuple, Type

import httpx
import pytest
import pytest_asyncio
from app.__main__ import main
from app.auth import Auth
from app.models import EventKind, ObjectKind, User
from app.schemas import EventSchema
from app.views import AppView
from client.config import DefaultsConfig
from client.requests import BaseRequests, UserChildEnum, UserRequests
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

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client", [{}], indirect=["client"])
    async def test_access_no_token(self, client: UserRequests):
        """Test `GET /users/{uuid}` without a token.

        Users should be able to access articles.
        """

        read, update, delete = await asyncio.gather(
            client.read(DEFAULT_UUID),
            client.update(DEFAULT_UUID, name="woops"),
            client.delete(DEFAULT_UUID),
        )
        if err := check_status(read, 200):
            raise err
        elif err := check_status(update, 401):
            raise err
        elif err := check_status(delete, 401):
            raise err

    # TODO: Add a test that collaborators can see this users account.
    @pytest.mark.asyncio
    async def test_get_user_public(self, client: UserRequests):
        """Test GET /users/{uuid} for a private user.

        Eventually the queries should deal with 'deactivation' via API
        eventually.
        """
        response = await client.update(DEFAULT_UUID, public=False)
        if err := check_status(response, 200):
            raise err

        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 204):
            raise err

        response = await client.update(DEFAULT_UUID, public=True)
        if err := check_status(response, 200):
            raise err

        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 200):
            raise err
        result = response.json()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_user_deleted(self, client: UserRequests):
        """Test `GET /users/{uuid}` on a user that has been deleted.

        This endpoint should state that the user has been deleted but provide a
        response with a `404` status code."""

        async def get_all(status) -> Tuple[httpx.Response, ...]:
            res = await asyncio.gather(
                client.read(DEFAULT_UUID),
                client.read_child(UserChildEnum.collections, DEFAULT_UUID),
                client.read_child(UserChildEnum.documents, DEFAULT_UUID),
            )
            if err := next((check_status(rr, status) for rr in res), None):
                raise err
            return res

        async def delete(restore=False):
            response = await client.delete(DEFAULT_UUID, restore=restore)
            event = EventSchema.model_validate_json(response.content)
            restore_str = "restore" if restore else "delete"
            assert event.detail == f"User {restore_str}d."
            assert event.kind == EventKind.delete
            assert event.uuid_parent is None
            assert isinstance(event.children, list)

            for child in event.children:
                assert child.kind == EventKind.delete
                assert child.uuid_parent == event.uuid
                if child.kind_obj == ObjectKind.document:
                    assert child.detail == f"Document {restore_str}d."
                elif child.kind_obj == ObjectKind.collection:
                    assert child.detail == f"Collection {restore_str}d."
                else:
                    raise AssertionError(f"Unexpected event with `{child.kind_obj=}`.")

        res = await get_all(200)
        _, res_docs, res_coll = res
        assert len(res_docs.json()), "Expected user to have documents."
        assert len(res_coll.json()), "Expected user to have collections."

        await delete()

        res = await get_all(204)
        bad = list(rr.request.url for rr in res if rr.request.content)
        if len(bad):
            raise ValueError(
                f"Expected no user content for user `{DEFAULT_UUID}`, but "
                "content was not returned from the following endpoints "
                f"despirte returning a `204` status code: `{bad}`."
            )

        await delete(restore=True)

        res = await get_all(200)
        _, res_docs, res_coll = res
        assert len(res_docs.json()), "Expected user to have documents restored."
        assert len(res_coll.json()), "Expected user to have collections restored."

    @pytest.mark.asyncio
    async def test_patch_user(self, client: UserRequests):
        new_name = secrets.token_hex(4)
        good, bad = await asyncio.gather(
            *(client.update(uuid, name=new_name) for uuid in (DEFAULT_UUID, "99999999"))
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
        # NOTE: Don't worry about getting, there is a separate test for that.
        res = await client.delete(DEFAULT_UUID)
        if err := check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == DEFAULT_UUID
        assert event.uuid_obj == DEFAULT_UUID
        assert event.detail == "User deleted."
        n = len(event.children)

        res = await client.delete(DEFAULT_UUID, restore=True)
        if err := check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == DEFAULT_UUID
        assert event.uuid_obj == DEFAULT_UUID
        assert event.detail == "User restored."
        assert len(event.children) == n

    @pytest.mark.asyncio
    async def test_delete_user_not_owned(self, client: UserRequests):
        res = await client.delete("99999999")
        if err := check_status(res, 403):
            raise err
        assert (
            res.json()["detail"] == "Users can only delete/restore their own account."
        )
