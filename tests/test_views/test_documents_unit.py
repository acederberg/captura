# =========================================================================== #
import functools
import secrets
from typing import ClassVar

import pytest
from pydantic import TypeAdapter
from sqlalchemy import join, select

# --------------------------------------------------------------------------- #
from app.controllers.access import H
from app.err import (
    ErrAccessDocumentGrantBase,
    ErrAccessDocumentGrantInsufficient,
    ErrAccessDocumentPending,
    ErrDetail,
    ErrObjMinSchema,
)
from app.fields import Format, KindObject, Level, LevelHTTP, PendingFrom
from app.models import Document
from app.schemas import AsOutput, DocumentSchema, OutputWithEvents, UserSchema, mwargs
from client.requests import Requests
from client.requests.base import params
from tests.dummy import DummyProvider, GetPrimaryKwargs
from tests.test_views.util import BaseEndpointTest, BaseEndpointTestPrimaryCreateMixins


class CommonDocumentTests(BaseEndpointTest):
    method: ClassVar[H]
    adapter = TypeAdapter(AsOutput[DocumentSchema])
    adapter_w_events = TypeAdapter(OutputWithEvents[DocumentSchema])

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests)

        requests.context.auth_exclude = True
        res = await fn(secrets.token_urlsafe(8))
        httperr = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, httperr):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_not_found_404(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests)
        uuid = secrets.token_urlsafe(9)
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid,
                kind_obj=KindObject.document,
            ),
        )
        res = await fn(uuid)
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests)
        (document,) = dummy.get_documents(
            1,
            GetPrimaryKwargs(deleted=True),
            level=Level.view,
        )
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=document.uuid,
                kind_obj=KindObject.document,
            ),
        )
        res = await fn(document.uuid)
        if err := self.check_status(requests, res, 410, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_no_grant(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Should always raise 403 when no grant on private document."""

        (document,) = dummy.get_documents(1, level=Level.view)
        grant = dummy.get_document_grant(document)
        session = dummy.session
        document.public = False
        session.add(document)
        session.delete(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid)
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentGrantBase],
            detail=ErrAccessDocumentGrantBase(
                msg=ErrAccessDocumentGrantBase._msg_dne,
                uuid_user=dummy.user.uuid,
                uuid_document=document.uuid,
                level_grant_required=LevelHTTP[self.method.name].value,
            ),
        )
        if err := self.check_status(requests, res, 403, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_pending(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test cannot use when ownership is pending."
        (document,) = dummy.get_documents(
            1, level=Level.own, pending=True, exclude_pending=False
        )
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_document_grant(document)
        assert not grant.deleted, "Grant should not be deleted."
        assert grant.pending, "Grant should be pending."

        grant.pending_from = PendingFrom.granter
        assert grant.level == Level.own
        session = dummy.session
        if self.method == H.GET:
            document.public = False
            session.add(document)

        session.add(grant)
        session.commit()
        # session.reset()

        fn = self.fn(requests)
        res = await fn(document.uuid)
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentPending],
            detail=ErrAccessDocumentPending(
                pending_from=PendingFrom.granter,
                msg=ErrAccessDocumentPending._msg_grant_pending,
                uuid_document=document.uuid,
                uuid_user=dummy.user.uuid,
                level_grant=Level.own,
                level_grant_required=LevelHTTP[self.method.name].value,
                uuid_grant=grant.uuid,
            ),
        )
        if err := self.check_status(requests, res, 403, httperr):
            raise err

    # NOTE: Does not apply to all endpoint (no insufficient for create or read)
    #       see tests in children.
    async def forbidden_403_insufficient(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test cannot access when not an owner."
        (document,) = dummy.get_documents(1, level=Level.view)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_document_grant(document)
        assert not grant.deleted, "Grant should not be deleted."
        assert not grant.pending, "Grant should not be pending."
        grant.level = Level.view

        session = dummy.session
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid)

        http_err = mwargs(
            ErrDetail[ErrAccessDocumentGrantInsufficient],
            detail=dict(
                msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
                uuid_document=document.uuid,
                uuid_user=dummy.user.uuid,
                uuid_grant=grant.uuid,
                level_grant=Level.view,
                level_grant_required=LevelHTTP[self.method.name].value,
            ),
        )
        if err := self.check_status(requests, res, 403, http_err):
            raise err


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestDocumentsRead(CommonDocumentTests):
    method = H.GET

    def fn(self, requests: Requests):
        return requests.documents.read

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (document,) = dummy.get_documents(1, level=Level.view)
        (document_other,) = dummy.get_documents(
            1, GetPrimaryKwargs(public=True), other=True
        )

        # NOTE: Can access own documents.
        fn = self.fn(requests)
        res = await fn(document.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.document
        assert data.kind_nesting is None
        assert data.data.uuid == document.uuid

        # NOTE: Can access private documents of others.
        fn = self.fn(requests)
        res = await fn(document_other.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.document
        assert data.kind_nesting is None
        assert data.data.uuid == document_other.uuid


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestDocumentsCreate(
    BaseEndpointTestPrimaryCreateMixins,
    CommonDocumentTests,
):
    method = H.POST

    def fn(self, requests: Requests, for_common: bool = True):
        req = requests.documents.create
        if for_common:

            def wrapper(uuid: str):
                return req(
                    name="TestDocumentsCreate",
                    description="TestDocumentsCreate",
                    format=Format.md,
                    content="TestDocumentsCreate.fn",
                )

            return wrapper
        return req

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests, for_common=False)
        uu = secrets.token_urlsafe(11)
        res = await fn(  # type: ignore
            name=f"TestDocumentsCreate.test_success_200-{uu}",  # type: ignore
            description="TestDocumentsCreate.test_success_200",  # type: ignore
            format=Format.md,  # type: ignore
            content="TestDocumentsCreate.test_success_200",  # type: ignore
        )
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.document
        assert uu in data.data.name

    # ----------------------------------------------------------------------- #
    # Tests That do not Apply.

    @pytest.mark.skip
    async def test_forbidden_403_no_grant(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Excluded since there is no resource to access."""
        assert False

    @pytest.mark.skip
    async def test_forbidden_403_pending(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Excluded since there is no resource to access."""
        assert False


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestDocumentsUpdate(CommonDocumentTests):
    method = H.PATCH

    def fn(self, requests: Requests, for_common: bool = True):
        req = requests.documents.update
        if for_common:
            return functools.partial(req, name="TestDocumentsUpdate")

        return req

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        await self.forbidden_403_insufficient(dummy, requests)

    @pytest.mark.asyncio
    async def test_malformed_422_content(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Cannot update content through this endpoint."""

        (document,) = dummy.get_documents(1, level=Level.own)
        client = requests.client

        res = await client.patch(
            requests.context.url(f"/documents/{document.uuid}"),
            params=dict(content="foobar"),
            headers=requests.context.headers,
        )
        if err := self.check_status(requests, res, 422):
            raise err

        content = res.json()

        assert (detail := content.get("detail")) is not None
        assert len(detail)

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Modifiers can update content and metadata."""

        (document,) = dummy.get_documents(1, level=Level.own)
        grant = dummy.get_document_grant(document)

        session = dummy.session
        grant.deleted, grant.level = (False, Level.modify)
        session.add(grant)
        session.commit()
        session.expire_all()

        # NOTE: Update.
        fn = self.fn(requests, for_common=False)
        name = f"TestDocumentsUpdate.test_success_200-{secrets.token_urlsafe()}"
        res = await fn(document.uuid, name=name)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.document
        assert data.kind_nesting is None
        assert len(data.events) == 1
        assert len(data.events[0].children) == 1

        # NOTE: Verify with DB and API.
        fn_read = requests.documents.read
        res = await fn_read(document.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.document
        assert data.kind_nesting is None
        assert data.data.uuid == document.uuid

        session.reset()
        q = select(Document).where(Document.uuid == document.uuid)
        document_db = session.scalar(q)
        session.refresh(document_db)

        assert document_db is not None
        assert document_db.name == data.data.name == name


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestDocumentsDelete(CommonDocumentTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        req = requests.documents.delete
        return req

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        await self.forbidden_403_insufficient(dummy, requests)

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):

        document = dummy.get_documents(1, level=Level.own)
        fn, fn_read = self.fn(requests), requests.documents.read
        fn_read_grants = requests.grants.documents.read
        fn_read_assigns = requests.assignments.documents.read
