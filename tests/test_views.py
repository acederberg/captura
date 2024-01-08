import asyncio
import json
import secrets
import sys
from typing import Any, AsyncGenerator, Tuple, Type

import httpx
import pytest
import pytest_asyncio
import yaml
from app import __version__, util
from app.__main__ import main
from app.auth import Auth
from app.models import AssocUserDocument, Document, EventKind, Level, ObjectKind, User
from app.schemas import EventSchema, GrantSchema, UserSchema
from app.views import AppView, GrantView
from client.config import DefaultsConfig
from client.requests import BaseRequests, GrantRequests, UserChildEnum, UserRequests
from sqlalchemy import select, update
from sqlalchemy.orm import Session, make_transient, sessionmaker

from .conftest import PytestClientConfig

CURRENT_APP_VERSION = __version__
DEFAULT_UUID_DOCS: str = "aaa-aaa-aaa"
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
        msg += f"\nAuthorization: {auth}"

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

    @pytest.mark.asyncio
    async def test_create(self, client: UserRequests):
        def check_common(event: EventSchema):
            assert event.uuid_user is not None
            if not client.config.remote:
                assert event.api_version == CURRENT_APP_VERSION
            assert event.api_origin == "POST /users"
            assert event.kind == EventKind.create

        p = util.Path.test_assets("test-user-create.yaml")
        res = await client.create(p)
        if err := check_status(res, 201):
            raise err

        # NOTE: The expected number of results changes when the document is
        #       changed. Per the note in the document, do not change it without
        #       testing it first.
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.detail == "User created."
        assert event.kind_obj == ObjectKind.user

        n_collections, n_documents = 0, 0
        for ee in event.children:
            check_common(event)
            if ee.kind_obj == ObjectKind.collection:
                assert ee.detail == "Collection created."
                n_collections += 1
            elif ee.kind_obj == ObjectKind.document:
                assert ee.detail == "Document created."
                n_documents += 1
            else:
                raise AssertionError(
                    f"Expected no events of `kind_obj={event.kind_obj}`."
                )

        # Verify counts
        if n_collections != 4:
            raise AssertionError("Expected to find four collections.")
        elif n_documents != 3:
            raise AssertionError("Expected to find three documents.")

        uuid: str = event.uuid_user  # type: ignore
        res = await asyncio.gather(
            client.read(uuid),
            client.read_child(UserChildEnum.documents, uuid),
            client.read_child(UserChildEnum.collections, uuid),
        )
        if err := next((check_status(rr, 200) for rr in res), None):
            raise err

        res_user, res_docs, res_collections = res
        user = UserSchema.model_validate_json(res_user.content)
        assert user.name == "test create"
        assert user.description == "test user for test create."
        assert user.url_image == "http://github.com/acederberg"
        assert user.uuid == uuid

        documents, collections = res_docs.json(), res_collections.json()
        assert len(documents) == 3
        assert len(collections) == 4


class TestGrantView(BaseTestViews):
    T = GrantRequests

    @pytest.mark.asyncio
    async def test_read_grants_user(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        """Test functionality of `GET /users/grants`."""
        res = await client.read_user("00000000")
        if err := check_status(res, 200):
            raise err

        raw = res.json()
        assert isinstance(raw, list)

        grants = list(GrantSchema.model_validate(item) for item in raw)
        assert (n := len(grants)) > 0, "Expected grants."

        # Grants should specify only one user.
        uuids, uuids_users = zip(*((gg.uuid, gg.uuid_user) for gg in grants))
        assert set(uuids_users) == {"00000000"}

        # Number of grants should equal the number of entries the owner has in
        # this table.
        with sessionmaker() as session:
            results = list(
                session.execute(
                    select(AssocUserDocument).where(AssocUserDocument.uuid.in_(uuids))
                ).scalars()
            )
            assert len(results) == n

    @pytest.mark.asyncio
    async def test_read_grants_user_only_user(self, client: GrantRequests):
        """Test that a user can only read their own grants.

        In the future, admins will be able to read grants of arbitrary users.
        """
        res = await client.read_user("99999999")
        if err := check_status(res, 403):
            raise err
        assert res.json == dict(msg="Users can only read their own grants.")

    @pytest.mark.asyncio
    async def test_read_grants_document(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        # user_client = UserRequests(client=client.client, config=client.config)
        # res = await user_client.read_child(UserChildEnum.documents, DEFAULT_UUID)
        # if err := check_status(res, 200):
        #     raise err
        #
        # document_ids = list(item["uuid"] for item in res.json().values())
        # assert len(document_ids), "Expected documents for user."

        res = await client.read_document(DEFAULT_UUID_DOCS)
        if err := check_status(res, 200):
            raise err

        with sessionmaker() as session:
            user = session.execute(
                select(User).where(User.uuid == DEFAULT_UUID)
            ).scalar()
            assert user is not None
            assoc = session.execute(
                select(AssocUserDocument).where(
                    AssocUserDocument.id_user == user.id,
                    AssocUserDocument.id_document.in_(
                        select(Document.id).where(
                            Document.uuid == DEFAULT_UUID_DOCS,
                        )
                    ),
                )
            ).scalar()
            assert assoc is not None
            assert assoc.level == Level.own

            assoc.level = Level.view
            session.add(assoc)
            session.commit()

            res = await client.read_document(DEFAULT_UUID_DOCS)
            if err := check_status(res, 403):
                raise err

            result = res.json()["detail"]
            assert result["msg"] == "Insufficient grants to view document grants."

            session.delete(assoc)
            session.commit()

            res = await client.read_document(DEFAULT_UUID_DOCS)
            if err := check_status(res, 403):
                raise err

            result = res.json()["detail"]
            assert result["msg"] == "No permissions for document."

            make_transient(assoc)
            assoc.level = Level.own
            session.add(assoc)
            session.commit()

    @pytest.mark.asyncio
    async def test_delete_grant(self, client: GrantRequests):
        ...

    @pytest.mark.asyncio
    async def test_post_grant(self, client: GrantRequests):
        ...
