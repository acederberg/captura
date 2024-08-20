# =========================================================================== #
import secrets
from typing import Any, ClassVar, Dict, List

import httpx
import pytest
from pydantic import TypeAdapter
from sqlalchemy import select

# --------------------------------------------------------------------------- #
from captura.controllers.access import H
from captura.err import (
    ErrAccessDocumentCannotRejectOwner,
    ErrAccessDocumentGrantBase,
    ErrAccessDocumentGrantInsufficient,
    ErrAccessDocumentPending,
    ErrDetail,
    ErrObjMinSchema,
)
from captura.fields import KindObject, Level, LevelStr, PendingFrom, PendingFromStr
from captura.models import Document, Grant, uuids
from captura.schemas import (
    AsOutput,
    DocumentSchema,
    GrantSchema,
    KindNesting,
    OutputWithEvents,
    mwargs,
)
from legere.requests import Requests
from simulatus import DummyProvider
from tests.conftest import COUNT
from tests.test_views.util import BaseEndpointTest

N_CASES: int = 1

# Keeps manual assets out and bypasses reloading of other tables.


# =========================================================================== #


class CommonDocumentsGrantsTests(BaseEndpointTest):
    method: ClassVar[H]
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
        count: int,
    ):
        "Test unauthorized access."

        assert requests.context.auth_exclude is False, "Auth should not be excluded."

        (document,) = dummy.get_documents(1, level=Level.own)
        assert not document.deleted
        fn = self.fn(requests)

        requests.context.auth_exclude = True
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])
        requests.context.auth_exclude = False

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test cannot access when not an owner."
        (document,) = dummy.get_documents(1, level=Level.modify)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_document_grant(document)
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
                level_grant_required=Level.own,
            ),
        )
        if err := self.check_status(requests, res, 403, http_err):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_pending(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test cannot use when ownership is pending."
        kwargs: Dict[str, Any] = dict(pending=True, exclude_pending=False)
        (document,) = dummy.get_documents(1, level=Level.own, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_document_grant(document)
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
    async def test_forbidden_403_no_grant(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
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
        res = await fn(document.uuid, uuid_user=["abcdef1234"])
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentGrantBase],
            detail=ErrAccessDocumentGrantBase(
                msg=ErrAccessDocumentGrantBase._msg_dne,
                uuid_user=dummy.user.uuid,
                uuid_document=document.uuid,
                level_grant_required=Level.own,
            ),
        )
        if err := self.check_status(requests, res, 403, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
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
            ),
        )
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410_grant(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test cannot use grant is deleted."
        kwargs = dict(exclude_pending=False, exclude_deleted=False)
        (document,) = dummy.get_documents(1, level=Level.own, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        # NOTE: Deletedness should supercede pendingness.
        grant = dummy.get_document_grant(document)
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
            ),
        )
        if err := self.check_status(requests, res, 410, errhttp):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test deleted document"

        # NOTE: Select deleted documents with undeleted grants (not likely to
        #       happen but probably worth testing incase deletion is broken).
        #       `exclude_deleted` is `True` in `get_document_grant` since excluded
        #       documents are deleted.
        document = Document(
            name="test_not_found_404",
            description="test_not_found_404",
            deleted=True,
        )
        session = dummy.session
        session.add(document)
        session.commit()
        session.refresh(document)

        grant = Grant(
            id_document=document.id,
            id_user=dummy.user.id,
            level=Level.own,
            pending=False,
            deleted=False,
            pending_from=PendingFrom.created,
        )
        session.add(grant)
        session.commit()
        session.refresh(grant)

        assert grant.deleted is False, "Grant should not be deleted."
        assert grant.pending is False, "Grant should not be pending."

        # users = dummy.get_users(n=3)
        # uuid_user = uuids(users)
        # grants = tuple(Grant(id_document=document.id, id_user=uu.id) for uu in users)
        # tuple(map(session.merge, grants))

        errhttp = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=document.uuid,
                kind_obj=KindObject.document,
            ),
        )
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=dummy.user.uuid)
        if err := self.check_status(requests, res, 410, errhttp):
            raise err


# NOTE: Test classes will be per endpoint. They will be parameterized with many
#       dummies. I found it helpful to look directly at the documentation to
#       come up with tests. The goal here is to test at a very fine scale.
@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestDocumentsGrantsRead(CommonDocumentsGrantsTests):
    method = H.GET

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
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test a successful response."

        fn = self.fn(requests)
        (document,) = dummy.get_documents(1, level=Level.own)
        assert not document.deleted

        grant = dummy.get_document_grant(document)
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
    async def test_success_200_pending(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test the pending query parameter."

        fn = self.fn(requests)

        document = Document(
            name="test_success_200_pending",
            description="test_success_200_pending",
            deleted=False,
        )
        session = dummy.session
        session.add(document)
        session.commit()
        session.refresh(document)

        grant = Grant(
            id_document=document.id,
            id_user=dummy.user.id,
            level=Level.own,
            pending=False,
            deleted=False,
            pending_from=PendingFrom.created,
        )
        users = dummy.get_users(10, other=True)
        grants = [
            Grant(
                id_document=document.id,
                id_user=user.id,
                level=Level.view,
                pending=index % 2,
                deleted=False,
                pending_from=PendingFrom.granter,
            )
            for index, user in enumerate(users)
        ]
        session.add_all(grants)
        session.add(grant)
        session.commit()
        session.refresh(grant)

        uuid_user = list(uu.uuid for uu in users)
        n_users_min = len(uuid_user) // 2
        n_users_max = n_users_min + 1

        res = await fn(document.uuid, uuid_user=uuid_user, pending=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert all(
            item.pending
            and item.uuid_user in uuid_user
            and item.uuid_document == document.uuid
            for item in data.data
        )
        assert n_users_min <= len(data.data) <= n_users_max

        res = await fn(document.uuid, uuid_user=uuid_user, pending=False)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert all(
            not item.pending
            and item.uuid_user in uuid_user
            and item.uuid_document == document.uuid
            for item in data.data
        )
        assert n_users_min <= len(data.data) <= n_users_max

    @pytest.mark.asyncio
    async def test_success_200_pending_from(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test the pending_from query parameter."

        # NOTE: Should return nothing when `create` and `pending`. Want mix of
        #       user ids that are pending and not.
        fn = self.fn(requests)
        (document,) = dummy.get_documents(
            1,
            level=Level.own,
            pending_from=PendingFrom.created,
        )
        grant = dummy.get_document_grant(document)

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
        count: int,
    ):
        "Test the pending query parameter."

        # NOTE: Documents without grants are not generated by `dummy` as every
        #       document generated has an ownership grant, just like those that
        #       should be generated by the API.
        (document,) = dummy.get_documents(1, level=Level.own)
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


@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestDocumentsGrantsRevoke(CommonDocumentsGrantsTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        return requests.grants.documents.revoke

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn_read = requests.grants.documents.read

        # NOTE: Create a document.
        res_document = await requests.documents.create(
            name="From TestDocumentsGrantsRevoke.test_success_200",
            description="Foobar",
        )
        if err := self.check_status(requests, res_document):
            raise err

        document_output = AsOutput[DocumentSchema].model_validate_json(
            res_document.content
        )
        uuid_document = document_output.data.uuid

        # NOTE: Verify that grant was generated.
        res_document_grants = await fn_read(uuid_document)
        if err := self.check_status(requests, res_document_grants):
            raise err

        assert (
            len(res_document_grants.json()["data"]) == 1
        ), "There should be exactly one grant."

        # NOTE: Database sessions are included in the dummy which results in some
        #       issues reading.
        # (session := dummy.session).expire_all()
        # document = session.scalar(
        #     select(Document).where(Document.uuid == document_output.data.uuid)
        # )
        # assert document is not None

        # NOTE: Get users to create grants.
        res_users = await requests.users.search(
            dummy.user.uuid, randomize=True, limit=10
        )
        if err := self.check_status(requests, res_users):
            raise err

        res_users_json = res_users.json()
        assert res_users_json.get("kind") == "users"
        assert res_users_json.get("kind_nesting") == "list"

        assert (users := res_users_json.get("data")) is not None
        uuid_user = list(
            uuid
            for item in users
            if (uuid := item.get("uuid")) is not None and uuid != dummy.user.uuid
        )
        assert (n_users := len(uuid_user))
        assert all(item is not None for item in uuid_user)

        # NOTE: Create grants.
        res_invite = await requests.grants.documents.invite(
            uuid_document, uuid_user=uuid_user
        )
        if err := self.check_status(requests, res_invite):
            raise err

        res_invite_json = res_invite.json()
        assert (res_invite_data := res_invite_json.get("data")) is not None

        # ------------------------------------------------------------------- #
        # NOTE: Read grants created
        res_read = await fn_read(uuid_document, uuid_user=uuid_user, pending=True)
        if err := self.check_status(requests, res_read):
            raise err

        res_read_json = res_read.json()
        assert (n_grants := len(res_read_json["data"])) == n_users

        res_read = await fn_read(uuid_document, uuid_user=uuid_user, pending=False)
        if err := self.check_status(requests, res_read):
            raise err
        res_read_json = res_read.json()
        assert (len(res_read_json["data"])) == 0

        # NOTE: Read own grants.
        res_read = await fn_read(uuid_document, uuid_user=[dummy.user.uuid])
        if err := self.check_status(requests, res_read):
            raise err

        assert len(res_read.json()["data"]) == 1

        # ------------------------------------------------------------------- #
        # NOTE: Now delete.
        fn = self.fn(requests)
        res = await fn(uuid_document, uuid_user=uuid_user, pending=True)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert len(data.events) == 1
        assert len(data.data) == n_grants

        # NOTE: Should return empty when filtering by deleted ids.
        res_read = await fn_read(uuid_document, uuid_user=uuid_user)
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind is None

        # TODO: Check indepotence.
        res = await fn(uuid_document, uuid_user=uuid_user)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None

        # NOTE: Test force.
        res = await fn(uuid_document, uuid_user=uuid_user, force=True, pending=True)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert len(data.data) == n_grants
        assert len(data.events) == 1
        assert len(data.events[0].children) == n_grants

        # NOTE: Indempotant force.
        res = await fn(uuid_document, uuid_user=uuid_user, force=True, pending=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None

    @pytest.mark.asyncio
    async def test_forbidden_403_cannot_reject_other_owner(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        # NOTE: New document with multiple owners.
        document = Document(
            name="test_forbidden_403_cannot_reject_other_owner",
            description="test_forbidden_403_cannot_reject_other_owner",
            public=True,
            deleted=False,
        )

        session = dummy.session
        session.add(document)
        session.commit()
        session.refresh(dummy.user)

        users = dummy.get_users(other=True, n=5)
        session.add(
            grant := Grant(
                id_user=dummy.user.id,
                id_document=document.id,
                level=Level.own,
                pending=False,
                deleted=False,
                pending_from=PendingFrom.created,
                children=(
                    grants := list(
                        Grant(
                            id_user=user.id,
                            id_document=document.id,
                            level=Level.own,
                            pending=False,
                            deleted=False,
                            pending_from=PendingFrom.granter,
                        )
                        for user in users
                    )
                ),
            )
        )
        session.commit()
        tuple(map(session.refresh, grants))
        session.refresh(grant)

        # NOTE: Now try to reject other owner.
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[uu.uuid for uu in users])
        httperr = mwargs(
            ErrDetail[ErrAccessDocumentCannotRejectOwner],
            detail=ErrAccessDocumentCannotRejectOwner(
                msg=ErrAccessDocumentCannotRejectOwner._msg_cannot_reject_owner,
                uuid_user_revoker=dummy.user.uuid,
                uuid_user_revokees=uuids(users),
                uuid_document=document.uuid,
            ),
        )

        if err := self.check_status(requests, res, 403, httperr):
            raise err


@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestDocumentsGrantsApprove(CommonDocumentsGrantsTests):
    method = H.PATCH

    def fn(self, requests: Requests):
        return requests.grants.documents.approve

    @pytest.mark.asyncio
    async def test_forbidden_403_pending_from(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        """Test that grants with ``pending_from != granter`` cannot be approved
        with this endpoint.
        """
        session = dummy.session
        (document,) = dummy.get_documents(
            1, level=Level.own, pending_from=PendingFrom.created
        )
        grant = dummy.get_document_grant(document)
        assert not grant.pending
        assert not grant.deleted
        assert grant.pending_from == PendingFrom.created

        # NOTE: Create grant for other user.
        (user_other,) = dummy.get_users(1)
        uuid_user = [user_other.uuid]
        session.add(user_other)
        q_grant_other = select(Grant).where(
            Grant.id_document == document.id,
            Grant.id_user == user_other.id,
        )
        grant_other_init = session.scalar(q_grant_other)
        if grant_other_init is not None:
            session.delete(grant_other_init)
            session.commit()

        session.add(
            grant_other := Grant(
                id_user=user_other.id,
                id_document=document.id,
                level=Level.view,
                pending=True,
                deleted=False,
                pending_from=PendingFrom.grantee,
            )
        )
        session.commit()
        session.refresh(grant_other)

        # NOTE: Read the grant and verify that it is a pending state. Also
        #       test that the pending result does not show up in non pending
        #       reads.
        fn_read = requests.grants.documents.read
        res_read = await fn_read(document.uuid, uuid_user=uuid_user)
        res_read_pending = await fn_read(
            document.uuid, uuid_user=uuid_user, pending=True
        )
        if err := self.check_status(requests, res_read_pending):
            raise err
        elif err := self.check_status(requests, res_read):
            raise err

        data_read = self.adapter.validate_json(res_read.content)
        data_read_pending = self.adapter.validate_json(res_read_pending.content)
        assert data_read.kind is None
        assert data_read_pending.kind is KindObject.grant

        # NOTE: Approve the grant.
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[user_other.uuid])
        err = mwargs(
            ErrDetail[ErrAccessDocumentPending],
            detail=ErrAccessDocumentPending(
                msg=ErrAccessDocumentPending._msg_grant_pending,
                uuid_document=document.uuid,
                uuid_user=dummy.user.uuid,
                level_grant_required=Level.own,
                level_grant=Level.own,
                uuid_grant=grant_other.uuid,
                pending_from=PendingFrom.grantee,
            ),
        )
        if err := self.check_status(requests, res):
            raise err

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test with grants pending with the correct pending_from value"

        # NOTE: Create owned document and find some user uuids.
        document = Document(
            name="TestDocumentsGrantsApprove.test_success_200",
            description="TestDocumentsGrantsApprove.test_success_200",
            public=True,
            deleted=False,
        )
        session = dummy.session
        session.add(document)
        session.commit()
        session.refresh(document)

        session.add(
            Grant(
                id_user=dummy.user.id,
                id_document=document.id,
                level=Level.own,
                pending=False,
                pending_from=PendingFrom.created,
            )
        )
        session.commit()

        # NOTE: Create grants, verify with db.
        uuid_user = list(uu.uuid for uu in dummy.get_users(other=True, n=10))
        n_users = len(uuid_user)
        res = await requests.g.d.invite(document.uuid, uuid_user=uuid_user)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)

        assert len(data.data) == n_users
        assert all(
            gg.pending_from == PendingFrom.grantee
            and gg.pending
            and gg.level == Level.view
            for gg in data.data
        )
        assert sorted(uuid_user) == sorted(gg.uuid_user for gg in data.data)

        # NOTE: Verify with API. Results should not include user grant.
        fn_read = requests.grants.documents.read
        res_pending = await fn_read(document.uuid, uuid_user=uuid_user, pending=True)
        if err := self.check_status(requests, res_pending):
            raise err

        data = self.adapter.validate_json(res_pending.content)
        assert data.kind == KindObject.grant
        assert data.kind_nesting is KindNesting.array
        assert len(data.data) == (n_users)
        assert all(gg.pending for gg in data.data)

        res_pending = await fn_read(document.uuid, uuid_user=uuid_user)
        if err := self.check_status(requests, res_pending):
            raise err

        data = self.adapter.validate_json(res_pending.content)
        assert data.kind is None

        # NOTE: Indempotent.
        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_user)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.events) == 1
        assert not len(data.events[0].children)

        # NOTE: Check data returned and database.
        data = self.adapter_w_events.validate_json(res.content)
        assert data.events is not None

        dummy.session.reset()
        for item in data.data:
            assert not item.pending
            assert item.uuid in uuid_user

            item_db = dummy.session.get(Grant, item.uuid)
            assert item_db is not None
            assert not item_db.pending
            assert item_db.uuid_user in uuid_user

        # TODO: check events

        # NOTE: Reading should result in empty since all approved.
        #       Stuck bc caching wierdness. Used the token printed  by the
        #       console handler and user `client` with the global `--token`
        #       and did not get this strange result.

        # res = await fn_read(
        #     document.uuid,
        #     uuid_user=uuid_users,
        #     pending=True,
        # )
        # if err := self.check_status(requests, res_pending):
        #     raise err
        # # input()
        #
        # data = self.adapter.validate_json(res_pending.content)
        # if data.kind is not None:
        #     requests.context.console_handler.print_request(res.request, res)
        #     raise AssertionError("Expected empty result after all grants approved.")


@pytest.mark.parametrize(
    "count",
    [count for count in range(COUNT)],
)
class TestDocumentsGrantsInvite(CommonDocumentsGrantsTests):
    method = H.POST

    def fn(self, requests: Requests):
        return requests.grants.documents.invite

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (document,) = dummy.get_documents(1, level=Level.own)
        users = dummy.get_users(5)

        fn = self.fn(requests)
