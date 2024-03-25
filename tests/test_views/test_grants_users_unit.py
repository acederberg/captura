import asyncio
import secrets
from os import walk
from typing import List, Tuple

import httpx
import pytest
from app.err import ErrAccessUser, ErrDetail, ErrObjMinSchema
from app.fields import KindObject, Level, LevelStr, PendingFrom, PendingFromStr
from app.models import Document, Grant
from app.schemas import (AsOutput, GrantSchema, KindNesting, OutputWithEvents,
                         mwargs)
from client.requests import Requests
from pydantic import TypeAdapter
from tests.dummy import DummyProvider, GetPrimaryKwargs
from tests.test_views.util import BaseEndpointTest


class CommonUsersGrantsTests(BaseEndpointTest):

    adapter = TypeAdapter(AsOutput[List[GrantSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[GrantSchema]])

    def check_data(
        self,
        dummy: DummyProvider,
        data: AsOutput[List[GrantSchema]] | OutputWithEvents[List[GrantSchema]],
        *,
        level: Level | None = None,
        pending: bool = False,
        deleted: bool = False,
    ) -> None:

        assert len(data.data)
        assert data.kind == KindObject.grant
        assert data.kind_nesting == KindNesting.array

        for grant in data.data:

            _grant_loaded = dummy.session.get(Grant, grant.uuid)
            assert _grant_loaded is not None
            assert _grant_loaded.deleted is deleted
            assert grant.pending is pending
            assert _grant_loaded.pending is pending

            if level is None:
                continue 

            assert grant.level.value >= level.value

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test unauthorized access."

        (user,) = dummy.get_users(1)
        documents = dummy.get_documents(4)
        uuid_documents = Document.resolve_uuid(dummy.session, documents)

        fn = self.fn(requests)
        requests.context.auth_exclude = True

        res = await fn(user.uuid, uuid_document=[*uuid_documents])

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_forbidden_403(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        """User must be logged in as user."""
        user, (user_other,) = dummy.user, dummy.get_users(1, GetPrimaryKwargs(deleted=False))
        assert user.uuid != user_other.uuid
        assert user.deleted is False

        print(f"{user.uuid=}")
        print(f"{user_other.uuid=}")

        documents = dummy.get_documents(5)
        uuid_documents = Document.resolve_uuid(dummy.session, documents)

        fn = self.fn(requests)

        res = await fn(user_other.uuid, uuid_document=uuid_documents)
        err_content = mwargs(
            ErrDetail[ErrAccessUser],
            detail=ErrAccessUser(
                msg=ErrAccessUser._msg_only_self,
                uuid_user=user_other.uuid,
                uuid_user_token=user.uuid,
            ),
        )

        if err := self.check_status(requests, res, 403, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test not found response with bad document uuid."

        uuid_dne = secrets.token_urlsafe(9)
        uuid_documents = Document.resolve_uuid(dummy.session, dummy.get_documents(5))
        fn = self.fn(requests)

        res = await fn(uuid_dne, uuid_document=uuid_documents)
        err_content = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_dne,
                kind_obj=KindObject.user,
            ),
        )

        if err := self.check_status(requests, res, 404, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test deleted document"

        session, user = dummy.session, dummy.user
        user.deleted = True
        session.add(user)
        session.commit()

        uuid_documents = Document.resolve_uuid(dummy.session, dummy.get_documents(5))
        fn = self.fn(requests)

        res = await fn(user.uuid, uuid_document=uuid_documents)
        err_content = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=user.uuid,
                kind_obj=KindObject.user,
            ),
        )
        if err := self.check_status(requests, res, 410, err_content):
            raise err


class TestUsersGrantsRequest(CommonUsersGrantsTests):
    "For example requesting access to a document."

    def fn(self, requests: Requests):
        return requests.grants.users.request

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        "Test requesting a grant. Ask for access and verify the grant."
        assert False

    # NOTE: Not too sure about this one. For now users can request access so
    #       long as they know the document uuid.
    @pytest.mark.skip
    async def test_forbidden_403_only_public_documents(
        self, dummy: DummyProvider, requests: Requests
    ):
        """Test requesting a grant on a public document.

        Cannot ask for access to a private document, but filtering by private
        documents should be allowed for all other endpoint methods.
        """
        assert False


class TestUsersGrantsRead(CommonUsersGrantsTests):
    def fn(self, requests: Requests):
        return requests.grants.users.read


    @pytest.mark.asyncio
    async def test_success_200_random_documents(self, dummy: DummyProvider, requests: Requests):
        """Test user can read own grants.

        In this case this might be empty - such behaviour is desired. This
        test just verifies that filtering with bad ``uuid_document`` values
        will not raise errors.
        """

        kwargs = GetPrimaryKwargs(deleted=False)
        session, user = dummy.session, dummy.user
        user.deleted = False
        session.add(user)
        session.commit()

        assert not user.deleted
        documents = dummy.get_documents(5, kwargs)

        assert all(dd.deleted is False for dd in documents)

        uuid_document = list(Document.resolve_uuid(session, documents))

        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res, 200):
            raise err

        # NOTE: Do not use check data! It assumes anything is known about
        #       these grants.
        data = self.adapter.validate_json(res.content)
        assert data.kind is None or data.kind is KindObject.grant

    @pytest.mark.asyncio
    async def test_success_200_dne_documents(self, dummy: DummyProvider, requests: Requests):
        """Like `test_success_200_random_documents` but gaurenteed empty.
        """

        user = dummy.user
        uuid_document = list(secrets.token_urlsafe(9) for _ in range(5))

        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

    @pytest.mark.asyncio
    async def test_success_200_private(
        self, dummy: DummyProvider, requests: Requests
    ):
        """Test can read user pending grants for private documents."""

        user = dummy.user
        documents = dummy.get_user_documents(Level.view, n=5)
        uuid_document = list(Document.resolve_uuid(dummy.session, documents))

        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is not None
        self.check_data(dummy, data)

    @pytest.mark.asyncio
    async def test_success_200_pending_from(
        self, dummy: DummyProvider, requests: Requests
    ):
        """Test the `pending_from` query parameter."""

        user = dummy.user
        fn = self.fn(requests)

        pending_froms = list(PendingFrom)
        responses = await asyncio.gather(
            *(
                fn(user.uuid, pending_from=PendingFromStr[pending_from.name])
                for pending_from in pending_froms
            )
        )

        for pending_from, res in zip(pending_froms, responses):

            if err := self.check_status(requests, res, 200):
                raise err

            data = self.adapter.validate_json(res.content)
            self.check_data(dummy, data)
            assert all(item.pending_from == pending_from for item in data.data)

    @pytest.mark.asyncio
    async def test_success_200_level(
        self, dummy: DummyProvider, requests: Requests
    ):
        user = dummy.user
        fn = self.fn(requests)

        levels = list(Level)
        responses = await asyncio.gather(
            *(
                fn(user.uuid, level=LevelStr[level.name])
                for level in levels
            )
        )

        for level, res in zip(levels, responses):

            if err := self.check_status(requests, res):
                raise err

            data = self.adapter.validate_json(res.content)
            self.check_data(dummy, data, level=level)



class TestUsersGrantsReject(CommonUsersGrantsTests):
    def fn(self, requests: Requests):
        return requests.grants.users.reject

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        """User can remove own grants."""
        assert False


class TestUsersGrantsAccept(CommonUsersGrantsTests):
    def fn(self, requests: Requests):
        return requests.grants.users.accept

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        """User can accept own grants."""

        documents = dummy.get_user_documents(Level.view, n=5)
        uuid_document = list(Document.resolve_uuid(dummy.session, documents))

        for dd in documents:
            grant = dummy.get_document_grant(dd)
            if grant.pending_from == PendingFrom.created:
                continue

            grant.pending_from = PendingFrom.grantee
            grant.pending = True

        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        self.check_data(dummy, data, pending=False)

    @pytest.mark.asyncio
    async def test_success_200_uuid_document_dne(self, dummy: DummyProvider, requests: Requests):
        """Test filtering by using fake document uuids."""
        ...

    @pytest.mark.asyncio
    async def test_success_200_uuid_document(self, dummy: DummyProvider, requests: Requests):
        """User can accept own grants."""


    @pytest.mark.asyncio
    async def test_forbidden_403_pending_from(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        """Test that grants with ``pending_from != granter`` cannot be approved
        with this endpoint.
        """
        assert False
