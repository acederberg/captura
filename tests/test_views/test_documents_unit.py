# =========================================================================== #
import functools
import secrets
from typing import ClassVar

import pytest
from pydantic import TypeAdapter
from sqlalchemy import join

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
from app.schemas import AsOutput, DocumentSchema, OutputWithEvents, UserSchema, mwargs
from client.requests import Requests
from tests.dummy import DummyProvider, GetPrimaryKwargs
from tests.test_views.util import BaseEndpointTest, BaseEndpointTestPrimaryCreateMixins


class CommonDocumentTests(BaseEndpointTest):
    method: ClassVar[H]
    adapter = TypeAdapter(AsOutput[DocumentSchema])
    adapter_w_events = TypeAdapter(OutputWithEvents[DocumentSchema])

    @pytest.mark.asyncio
    async def test_unauthorized_401(self, dummy: DummyProvider, requests: Requests):
        fn = self.fn(requests)

        requests.context.auth_exclude = True
        res = await fn(secrets.token_urlsafe(8))
        httperr = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, httperr):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_not_found_404(self, dummy: DummyProvider, requests: Requests):
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
    async def test_deleted_410(self, dummy: DummyProvider, requests: Requests):
        fn = self.fn(requests)
        (document,) = dummy.get_documents(1, GetPrimaryKwargs(deleted=True))
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
        self, dummy: DummyProvider, requests: Requests
    ):
        """Should always raise 403 when no grant on private document."""

        (document,) = dummy.get_user_documents(Level.view, n=1)
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
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test cannot use when ownership is pending."
        kwargs = dict(pending=True, exclude_pending=False)
        (document,) = dummy.get_user_documents(Level.own, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_document_grant(document, **kwargs)
        assert not grant.deleted, "Grant should not be deleted."
        assert grant.pending, "Grant should be pending."

        grant.pending_from = PendingFrom.granter
        assert grant.level == Level.own
        session = dummy.session
        session.add(grant)
        session.commit()

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
        (document,) = dummy.get_user_documents(Level.view)
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


class TestDocumentsRead(CommonDocumentTests):
    method = H.GET

    def fn(self, requests: Requests):
        return requests.documents.read

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False


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
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False

    # ----------------------------------------------------------------------- #
    # Tests That do not Apply.

    @pytest.mark.skip
    async def test_forbidden_403_no_grant(
        self, dummy: DummyProvider, requests: Requests
    ):
        """Excluded since there is no resource to access."""
        ...

    @pytest.mark.skip
    async def test_forbidden_403_pending(
        self, dummy: DummyProvider, requests: Requests
    ):
        """Excluded since there is no resource to access."""
        ...


class TestDocumentsUpdate(CommonDocumentTests):
    method = H.PATCH

    def fn(self, requests: Requests, for_common: bool = True):
        req = requests.documents.update
        if for_common:
            return functools.partial(req, name="TestDocumentsUpdate")

        return req

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        await self.forbidden_403_insufficient(dummy, requests)

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False


class TestDocumentsDelete(CommonDocumentTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        req = requests.documents.delete
        return req

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        await self.forbidden_403_insufficient(dummy, requests)

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False
