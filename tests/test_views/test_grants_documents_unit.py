import secrets
from typing import List

import httpx
import pytest
from app.err import (ErrAccessDocumentCannotRejectOwner,
                     ErrAccessDocumentGrantBase,
                     ErrAccessDocumentGrantInsufficient,
                     ErrAccessDocumentPending, ErrDetail, ErrObjMinSchema)
from app.fields import KindObject, Level, LevelStr, PendingFrom, PendingFromStr
from app.models import Grant, User
from app.schemas import (AsOutput, GrantSchema, KindNesting, OutputWithEvents,
                         mwargs)
from client.requests import Requests
from pydantic import TypeAdapter
from sqlalchemy import false, func, literal_column, select, true
from tests.dummy import DummyProvider
from tests.test_views.util import BaseEndpointTest

N_CASES: int = 1

# Keeps manual assets out and bypasses reloading of other tables.


# =========================================================================== #


class CommonDocumentsGrantsTests(BaseEndpointTest):
    adapter = TypeAdapter(AsOutput[List[GrantSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[GrantSchema]])

    # ----------------------------------------------------------------------- #
    # Errors
    # NOTE: These should apply to all endpoints.;

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test unauthorized access."

        assert requests.context.auth_exclude is False, "Auth should not be excluded."

        document = dummy.get_document(Level.own)
        assert not document.deleted
        fn = self.fn(requests)
        requests.context.auth_exclude = True

        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test cannot access when not an owner."
        document = dummy.get_document(Level.modify)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_grant(document)
        assert not grant.deleted, "Grant should not be deleted."
        assert not grant.pending, "Grant should not be pending."
        grant.level = Level.modify

        session = dummy.session
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])

        http_err = mwargs(
            ErrDetail[ErrAccessDocumentGrantInsufficient],
            detail=dict(
                msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
                uuid_document=document.uuid,
                uuid_user=dummy.user.uuid,
                uuid_grant=grant.uuid,
                level_grant=Level.modify,
                level_grant_required=Level.own
            )
        )
        if err := self.check_status(requests, res, 403, http_err):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_pending(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test cannot use when ownership is pending."
        kwargs = dict(pending=True, exclude_pending=False)
        document = dummy.get_document(Level.own, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_grant(document, **kwargs)
        assert not grant.deleted, "Grant should not be deleted."
        assert grant.pending, "Grant should be pending."

        grant.pending_from = PendingFrom.granter
        assert grant.level == Level.own
        session = dummy.session
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentPending],
            detail=ErrAccessDocumentPending(
                pending_from=PendingFrom.granter,
                msg=ErrAccessDocumentPending._msg_grant_pending,
                uuid_document=document.uuid,
                uuid_user=dummy.user.uuid,
                level_grant=Level.own,
                level_grant_required=Level.own,
                uuid_grant=grant.uuid,
            ),
        )
        if err := self.check_status(requests, res, 403, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test not found response with bad document uuid."
        fn = self.fn(requests)
        uuid_obj = secrets.token_urlsafe(9)
        res = await fn(uuid_obj, uuid_user=[dummy.user.uuid])
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_obj,
                kind_obj=KindObject.document,
                # uuid_user=dummy.user.uuid,
            )
        )
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410_grant(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test cannot use grant is deleted."
        kwargs = dict(exclude_pending=False, exclude_deleted=False)
        document = dummy.get_document(Level.own, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        # NOTE: Deletedness should supercede pendingness.
        grant = dummy.get_grant(document, **kwargs)
        grant.deleted = True

        session = dummy.session
        session.add(grant)
        session.commit()

        assert grant.deleted, "Grant should be deleted."
        assert grant.level == Level.own, "Grant level should be `own`."

        # session = dummy.session
        # session.add(grant)
        # session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])

        errhttp = mwargs(
            ErrDetail[ErrAccessDocumentGrantBase],
            detail=ErrAccessDocumentGrantBase(
                msg=ErrAccessDocumentGrantBase._msg_dne,
                uuid_user=dummy.user.uuid,
                uuid_document=document.uuid,
                level_grant_required=Level.own,
            )
        )
        if err := self.check_status(requests, res, 410, errhttp):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test deleted document"

        # NOTE: Select deleted documents with undeleted grants (not likely to
        #       happen but probably worth testing incase deletion is broken).
        #       `exclude_deleted` is `True` in `get_grant` since excluded
        #       documents are deleted.
        document = dummy.get_document(Level.view, deleted=True)
        assert document.deleted, "Document should be deleted."

        grant = dummy.get_grant(document, exclude_deleted=False)
        grant.deleted = False
        grant.pending = False

        session = dummy.session
        session.add(grant)
        session.commit()

        assert grant.deleted is False, "Grant should not be deleted."
        assert grant.pending is False, "Grant should not be pending."

        uuid_user = self.document_user_uuids(dummy, document)

        errhttp = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=document.uuid,
                kind_obj=KindObject.document,
            )
        )
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_user)
        if err := self.check_status(requests, res, 410, errhttp):
            raise err


# NOTE: Test classes will be per endpoint. They will be parameterized with many
#       dummies. I found it helpful to look directly at the documentation to
#       come up with tests. The goal here is to test at a very fine scale.
class TestDocumentsGrantsRead(CommonDocumentsGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.read

    # ----------------------------------------------------------------------- #
    # Features

    def check_success(
        self,
        dummy: DummyProvider,
        requests: Requests,
        res: httpx.Response,
        *,
        pending: bool = False,
        level: Level | None = None,
        allow_empty: bool = False,
    ) -> AsOutput[List[GrantSchema]]:
        if err := self.check_status(requests, res, 200):
            raise err

        data: AsOutput[List[GrantSchema]]
        data = self.adapter.validate_json(res.content)

        if allow_empty and data.kind == None:
            return data

        assert data.kind == KindObject.grant
        assert data.kind_nesting == KindNesting.array

        # NOTE: Does not serve pending grants unless specified. Never serves
        #       deleted grants.
        for item in data.data:
            _item_loaded = dummy.session.get(Grant, item.uuid)
            assert _item_loaded is not None
            assert not _item_loaded.deleted, "Item should not be deleted."

            item_loaded = GrantSchema.model_validate(_item_loaded)
            assert item.pending is pending
            assert item_loaded.pending is pending

            if level is None:
                continue

            assert item.level.value >= level.value

        return data

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        "Test a successful response."

        fn = self.fn(requests)
        document = dummy.get_document(Level.own)
        assert not document.deleted

        grant = dummy.get_grant(document)
        assert grant.pending is False, "Grant should not be pending."
        assert grant.deleted is False, "Grant should not be deleted."
        # grant.deleted = False
        # grant.pending = False
        session = dummy.session
        session.add(grant)
        session.commit()

        res = await fn(document.uuid)
        self.check_success(dummy, requests, res, pending=False)

    @pytest.mark.asyncio
    async def test_success_200_pending(self, dummy: DummyProvider, requests: Requests):
        "Test the pending query parameter."

        fn = self.fn(requests)
        document = dummy.get_document(Level.own, exclude_pending=True)

        res = await fn(document.uuid, pending=True)
        self.check_success(dummy, requests, res, pending=True)

    @pytest.mark.asyncio
    async def test_success_200_pending_from(
        self, dummy: DummyProvider, requests: Requests
    ):
        "Test the pending_from query parameter."

        # NOTE: Should return nothing when `create` and `pending`. Want mix of
        #       user ids that are pending and not.
        fn = self.fn(requests)
        document = dummy.get_document(
            Level.own,
            pending_from=PendingFrom.created,
        )
        grant = dummy.get_grant(document)

        assert grant.deleted is False
        assert grant.pending is False

        # NOTE: Check against created. Created is never pending.
        user_uuids = [dummy.user.uuid]
        res = await fn(
            document.uuid,
            uuid_user=user_uuids,
            pending_from=PendingFromStr.created,
        )

        data = self.check_success(dummy, requests, res)
        assert len(data.data) == 1
        (grant,) = data.data
        assert grant.pending_from == PendingFrom.created

        # No results expected.
        res = await fn(
            document.uuid,
            uuid_user=user_uuids,
            pending_from=PendingFromStr.created,
            pending=True,
        )
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        # NOTE: Check against granter
        user_uuids = self.document_user_uuids(
            dummy, document, exclude_pending=False, limit=100
        )
        res = await fn(
            document.uuid,
            uuid_user=user_uuids,
            pending_from=PendingFromStr.granter,
            pending=True,
        )
        data = self.check_success(
            dummy,
            requests,
            res,
            pending=True,
            allow_empty=True,
        )
        assert all(item.pending_from == PendingFrom.granter for item in data.data)

    @pytest.mark.asyncio
    async def test_success_200_level(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test the pending query parameter."

        # NOTE: Documents without grants are not generated by `dummy` as every
        #       document generated has an ownership grant, just like those that
        #       should be generated by the API.

        document = dummy.get_document(Level.own, exclude_pending=False)
        assert not document.deleted

        fn = self.fn(requests)
        mt_count = 0
        for level in list(Level):
            for pending in (True, False):
                res = await fn(
                    document.uuid,
                    pending=pending,
                    level=LevelStr(level.name),
                )
                data = self.check_success(
                    dummy,
                    requests,
                    res,
                    level=level,
                    pending=pending,
                    allow_empty=True,
                )
                if data.kind is None:
                    mt_count += 1

        if mt_count == 6:
            raise AssertionError("All empty! Check dummy data.")


@pytest.mark.asyncio
class TestDocumentsGrantsRevoke(CommonDocumentsGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.revoke

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):

        document = dummy.get_document(Level.own, exclude_pending=True)
        assert not document.deleted

        q_users = document.q_select_users().where(Grant.level < Level.own)
        users = tuple(dummy.session.scalars(q_users))
        uuid_user = list(User.resolve_uuid(dummy.session, users))

        q_grants = document.q_select_grants(uuid_user)# type: ignore 
        q_grants = q_grants.where( Grant.level < Level.own) 
        q_grants = q_grants.where(Grant.deleted == false())
        grants = tuple(dummy.session.scalars(q_grants))
        assert (n_grants_init := len(grants)) > 0

        assert all(not grant.deleted and grant.level != Level.own
                   for grant in grants)

        # from app import util
        # util.sql(dummy.session, q_grants)
        # input("b4")
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_user)

        if err := self.check_status(requests, res, 200):
            raise err

        # Must reset because query is cached otherwise.
        dummy.session.reset()
        grants = tuple(dummy.session.scalars(q_grants))
        assert not len(grants), "No grants should be found since they should have been deleted."

        # TODO: Check events.

        # NOTE: Should return empty when filtering by deleted ids.
        fn_read = requests.grants.documents.read
        res_read = await fn_read(document.uuid, uuid_user=uuid_user)

        if err := self.check_status(requests, res_read, 200):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind is None

        res = await fn(document.uuid, uuid_user=uuid_user, force=True)

        # TODO: Check indepotence.

    @pytest.mark.asyncio
    async def test_forbidden_403_cannot_reject_other_owner(
        self, dummy: DummyProvider, requests: Requests
    ):
        document = dummy.get_document(Level.own)
        assert not document.deleted

        grant = dummy.get_grant(document)
        assert not grant.deleted

        # Gaurentee other owner
        session = dummy.session
        q = document.q_select_grants().where(Grant.level < Level.own).limit(1)
        grant_other = (session.scalar(q))
        assert isinstance(grant_other, Grant)
        assert grant_other.level != Level.own
        assert grant_other.deleted is False
        assert not grant_other.pending

        grant_other.level = Level.own
        session.add(grant_other)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[grant_other.uuid_user])
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentCannotRejectOwner],
            detail=ErrAccessDocumentCannotRejectOwner(
                msg=ErrAccessDocumentCannotRejectOwner._msg_cannot_reject_owner,
                uuid_user_revoker=dummy.user.uuid,
                uuid_user_revokees={grant_other.uuid_user},
                uuid_document=document.uuid,
            ),
        )


        if err:=self.check_status(requests, res, 403, httperr):
            raise err


class TestDocumentsGrantsApprove(CommonDocumentsGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.approve

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):

        # Get owned document
        document = dummy.get_document(Level.own)
        assert not document.deleted

        grant = dummy.get_grant(document)
        assert not grant.pending
        assert not grant.deleted
        assert grant.level == Level.own

        # NOTE: Find pending users and run against read.
        uuid_users_pending_from_granter = self.document_user_uuids(
            dummy,
            document,
            pending=True,
            exclude_pending=False,
            pending_from=PendingFrom.granter,
        )
        fn_read = requests.grants.documents.read
        res_pending = await fn_read(
            document.uuid,
            uuid_user=uuid_users_pending_from_granter,
            pending=True,
            pending_from=PendingFrom.created,
        )

        if err := self.check_status(requests, res_pending):
            raise err

        # NOTE: Data is gaurenteed nonempty since users known.
        data = self.adapter.validate_json(res_pending.content)
        assert data.kind is KindObject.grant
        assert data.kind_nesting is KindNesting.array

        uuid_users_pending_from_granter_recieved = set(item.uuid for item in data.data)
        assert len(uuid_users_pending_from_granter_recieved) == len(
            uuid_users_pending_from_granter
        )

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_users_pending_from_granter)
        if err := self.check_status(requests, res):
            raise err

        # Check data returned.
        data = self.adapter_w_events.validate_json(res.content)
        assert data.events is not None

        for item in data.data:
            assert not item.pending
            assert not item.deleted
            assert item.uuid in uuid_users_pending_from_granter_recieved

        # TODO: check events

        # NOTE: Reading should result in empty since all approved.
        res = await fn_read(
            document.uuid,
            uuid_user=uuid_users_pending_from_granter,
            pending=True,
        )
        if err := self.check_status(requests, res_pending):
            raise err

        data = self.adapter.validate_json(res_pending.content)
        assert data.kind is None

        # NOTE: Check indempotence.
        res = await fn(document.uuid, uuid_user=uuid_users_pending_from_granter)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert data.events is None


class TestDocumentsGrantsInvite(CommonDocumentsGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.invite

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False
