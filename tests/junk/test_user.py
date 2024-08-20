# =========================================================================== #
import asyncio
import secrets
from typing import Tuple

import httpx
import pytest
from sqlalchemy import update
from sqlalchemy.orm import Session, sessionmaker

# --------------------------------------------------------------------------- #
from captura import __version__, util
from captura.auth import Auth
from captura.models import ChildrenUser, Collection, Document, KindEvent, KindObject
from captura.schemas import EventSchema, UserSchema
from legere.requests import UserRequests

from . import util

# NOTE: The `requests` fixture must exist in module scope directly.
from .util import BaseTestViews


class TestUserViews(BaseTestViews):
    T = UserRequests

    @pytest.mark.asyncio
    async def test_get_user(self, client: UserRequests):
        "Test for the very limitted (at the moment) GET /users/{uuid}"
        # good is the default user, other is almost certain not to exist.
        good, bad = await asyncio.gather(
            *(client.read(uuid) for uuid in (util.DEFAULT_UUID, "foobarz"))
        )
        if err := util.check_status(good, 200):
            raise err
        elif err := util.check_status(bad, 404):
            raise err

        assert isinstance(result := good.json(), dict)
        assert result["uuid"] == util.DEFAULT_UUID

        assert bad.status_code == 404

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client", [{}], indirect=["client"])
    async def test_access_no_token(self, client: UserRequests):
        """Test `GET /users/{uuid}` without a token.

        Users should be able to access articles.
        """

        client.token = None
        read, update, delete = await asyncio.gather(
            client.read(util.DEFAULT_UUID),
            client.update(util.DEFAULT_UUID, name="woops"),
            client.delete(util.DEFAULT_UUID),
        )
        if err := util.check_status(read, 200):
            raise err
        elif err := util.check_status(update, 422):
            raise err
        elif err := util.check_status(delete, 422):
            raise err

        # TODO: Add tests that only public users and documents can be read.

    # TODO: Add a test that collaborators can see this users account.
    @pytest.mark.asyncio
    async def test_get_user_public(self, client: UserRequests, auth: Auth):
        """Test GET /users/{uuid} for a private user.

        Eventually the queries should deal with 'deactivation' via API
        eventually.
        """
        response = await client.update(util.DEFAULT_UUID, public=False)
        if err := util.check_status(response):
            raise err

        # Act like other user, should not be able to find.
        token_init = client.token
        client.token = (token_secondary := auth.encode({"uuid": "99d-99d-99d"}))
        response = await client.read(util.DEFAULT_UUID)
        if err := util.check_status(response, 403):
            raise err

        # Back to initial user.
        client.token = token_init
        response = await client.update(util.DEFAULT_UUID, public=True)
        if err := util.check_status(response):
            raise err

        # Now other user should be able to find.
        client.token = token_secondary
        response = await client.read(util.DEFAULT_UUID)
        if err := util.check_status(response):
            raise err
        result = response.json()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_user_deleted(self, client, sessionmaker: sessionmaker[Session]):
        """Test `GET /users/{uuid}` on a user that has been deleted.

        This endpoint should state that the user has been deleted but provide a
        response with a `404` status code."""

        async def get_all(
            status: int,
            status_children: int | None = None,
        ) -> Tuple[httpx.Response, ...]:
            res_read, *res = await asyncio.gather(
                client.read(util.DEFAULT_UUID),
                client.read(util.DEFAULT_UUID, ChildrenUser.documents),
                client.read(util.DEFAULT_UUID, ChildrenUser.collections),
            )

            status_children = status_children or status
            if err := util.check_status(res_read, status):
                raise err
            elif err := util.check_status(tuple(res), status_children):
                raise err
            return res_read, *res

        async def delete(restore=False):
            response = await client.delete(util.DEFAULT_UUID, restore=restore)
            if err := util.check_status(response, 200):
                raise err
            event = EventSchema.model_validate_json(response.content)
            restore_str = "restore" if restore else "delete"
            assert event.detail == f"User {restore_str}d."
            assert event.kind == KindEvent.delete
            assert event.uuid_parent is None
            assert isinstance(event.children, list)

            for child in event.children:
                assert child.kind == KindEvent.delete
                assert child.uuid_parent == event.uuid
                if child.kind_obj == KindObject.document:
                    assert child.detail == f"Document {restore_str}d."
                elif child.kind_obj == KindObject.collection:
                    assert child.detail == f"Collection {restore_str}d."
                else:
                    raise AssertionError(f"Unexpected event with `{child.kind_obj=}`.")

        with sessionmaker() as session:
            session.execute(update(Document).values(deleted=False))
            session.execute(update(Collection).values(deleted=False))
            session.commit()

        res = await get_all(200)
        _, res_docs, res_coll = res
        assert len(res_docs.json()), "Expected user to have documents."
        assert len(res_coll.json()), "Expected user to have collections."

        await delete()

        # User shold not exist, nor should children.
        res = await get_all(404)
        bad = list(rr.request.url for rr in res if rr.request.content)
        if len(bad):
            raise ValueError(
                f"Expected no user content for user `{util.DEFAULT_UUID}`, but "
                "content was not returned from the following endpoints "
                f"despite returning a `204` status code: `{bad}`."
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
            *(
                client.update(uuid, name=new_name)
                for uuid in (util.DEFAULT_UUID, "99d-99d-99d")
            )
        )
        if err := util.check_status(good):
            raise err
        elif err := util.check_status(bad, 403):
            raise err

        updated = await client.read(util.DEFAULT_UUID)
        if err := util.check_status(updated):
            raise err

        assert isinstance(result := updated.json(), dict)
        assert result["uuid"] == util.DEFAULT_UUID
        assert result["name"] == new_name

    @pytest.mark.asyncio
    async def test_delete_user(self, client: UserRequests):
        # NOTE: Don't worry about getting, there is a separate test for that.
        res = await client.delete(util.DEFAULT_UUID)
        if err := util.check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == util.DEFAULT_UUID
        assert event.uuid_obj == util.DEFAULT_UUID
        assert event.detail == "User deleted."
        n = len(event.children)

        res = await client.delete(util.DEFAULT_UUID, restore=True)
        if err := util.check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == util.DEFAULT_UUID
        assert event.uuid_obj == util.DEFAULT_UUID
        assert event.detail == "User restored."
        assert len(event.children) == n

    @pytest.mark.asyncio
    async def test_delete_user_not_owned(self, client: UserRequests):
        res = await client.delete("99d-99d-99d")
        if err := util.check_status(res, 403):
            raise err
        assert (
            res.json()["detail"] == "Users can only delete/restore their own account."
        )

    @pytest.mark.asyncio
    async def test_create(self, client: UserRequests):
        def check_common(event: EventSchema):
            assert event.uuid_user is not None
            if not client.config.remote:
                assert event.api_version == __version__
            assert event.api_origin == "POST /users"
            assert event.kind == KindEvent.create

        p = util.u.Path.test_assets("test-user-create.yaml")
        res = await client.create(p)
        if err := util.check_status(res, 201):
            raise err

        # NOTE: The expected number of results changes when the document is
        #       changed. Per the note in the document, do not change it without
        #       testing it first.
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.detail == "User created."
        assert event.kind_obj == KindObject.user

        n_collections, n_documents = 0, 0
        for ee in event.children:
            check_common(event)
            if ee.kind_obj == KindObject.collection:
                assert ee.detail == "Collection created."
                n_collections += 1
            elif ee.kind_obj == KindObject.document:
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
            client.read(uuid, ChildrenUser.documents),
            client.read(uuid, ChildrenUser.collections),
        )
        if err := next((util.check_status(rr, 200) for rr in res), None):
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
