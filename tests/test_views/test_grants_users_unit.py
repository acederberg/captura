# =========================================================================== #
import asyncio
from http import HTTPMethod
import json
import secrets
from typing import ClassVar, Dict, List

import pytest
from pydantic import TypeAdapter
from sqlalchemy import select

# --------------------------------------------------------------------------- #
from app.err import (
    ErrAccessUser,
    ErrAssocRequestMustForce,
    ErrDetail,
    ErrObjMinSchema,
    ErrUpdateGrantPendingFrom,
)
from app.fields import KindObject, Level, LevelStr, PendingFrom, PendingFromStr
from app.models import Document, Grant, User
from app.schemas import AsOutput, GrantSchema, KindNesting, OutputWithEvents, mwargs
from client.requests import Requests
from dummy import DummyProvider, GetPrimaryKwargs
from tests.test_views.util import BaseEndpointTest


class CommonUsersGrantsTests(BaseEndpointTest):
    method: ClassVar[HTTPMethod]
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
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test unauthorized access."

        (user,) = dummy.get_users(1)
        documents = dummy.get_documents(4, other=True)
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
        count: int,
    ):
        """User must be logged in as user."""
        user, (user_other,) = dummy.user, dummy.get_users(
            1, GetPrimaryKwargs(deleted=False)
        )
        assert user.uuid != user_other.uuid
        assert user.deleted is False

        documents = dummy.get_documents(5, other=True)
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

        if self.method == HTTPMethod.GET:
            err_content.detail.msg = ErrAccessUser._msg_private

        if err := self.check_status(requests, res, 403, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test not found response with bad document uuid."

        uuid_dne = secrets.token_urlsafe(9)
        uuid_documents = Document.resolve_uuid(
            dummy.session, dummy.get_documents(5, other=True)
        )
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
        count: int,
    ):
        "Test deleted document"

        session, user = dummy.session, dummy.user
        user.deleted = True
        session.add(user)
        session.commit()

        uuid_documents = Document.resolve_uuid(
            dummy.session, dummy.get_documents(5, other=True)
        )
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


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUsersGrantsRequest(CommonUsersGrantsTests):
    "For example requesting access to a document."

    method = HTTPMethod.POST

    def fn(self, requests: Requests):
        return requests.grants.users.request

    # NOTE: Many tests bc pain in the ass.
    @pytest.mark.asyncio
    async def test_success_200_simple(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test requesting a (single) grant that does not already exist and is not deleted."

        user, session = dummy.user, dummy.session
        (other_user,) = dummy.get_users(1)
        assert user.uuid != other_user.uuid

        other_dummy = DummyProvider(dummy.config, session, use_existing=other_user)
        (other_document,) = other_dummy.get_documents(1, level=Level.own)
        assert other_document.deleted is False

        q = (
            select(Grant)
            .join(User)
            .join(Document)
            .where(User.uuid == user.uuid, Document.uuid == other_document.uuid)
        )
        grants = tuple(session.scalars(q))
        for grant in grants:
            session.delete(grant)
        session.commit()

        # NOTE: Read the grant. No results should exist.
        fn_read = requests.grants.users.read
        uuid_other = [other_document.uuid]
        res_read, res_read_pending = await asyncio.gather(
            fn_read(user.uuid, uuid_document=uuid_other, pending=False),
            fn_read(user.uuid, uuid_document=uuid_other, pending=True),
        )
        if err := self.check_status(requests, res_read, 200):
            raise err
        elif err := self.check_status(requests, res_read_pending, 200):
            raise err

        data_read = self.adapter.validate_json(res_read.content)
        data_read_pending = self.adapter.validate_json(res_read.content)

        assert data_read.kind is None
        assert data_read_pending.kind is None

        # NOTE: Request grant.
        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=[other_document.uuid])
        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is KindObject.grant
        assert len(data.data)
        assert len(data.events) == 1
        assert len(data.events[0].children) == 1
        assert len(data.data) == 1

        # NOTE: Check with database.
        session.reset()
        grant = session.get(Grant, data.data[0].uuid)
        grant_data = data.data[0]
        assert grant is not None
        assert grant.pending
        assert grant_data.pending
        assert grant.pending_from == PendingFrom.granter == grant_data.pending_from
        assert grant.uuid_document == other_document.uuid == grant_data.uuid_document
        assert grant.uuid_user == user.uuid == grant_data.uuid_user

        # NOTE: Read again.
        res_read, res_read_pending = await asyncio.gather(
            fn_read(user.uuid, uuid_document=uuid_other, pending=False),
            fn_read(user.uuid, uuid_document=uuid_other, pending=True),
        )
        if err := self.check_status(requests, res_read, 200):
            raise err
        elif err := self.check_status(requests, res_read_pending, 200):
            raise err

        data_read = self.adapter.validate_json(res_read.content)
        data_read_pending = self.adapter.validate_json(res_read_pending.content)

        assert data_read.kind is None
        assert data_read_pending.kind is KindObject.grant

        # NOTE: Indempotent
        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=[other_document.uuid])
        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None

    @pytest.mark.asyncio
    async def test_bad_request_400(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test what happens when requesting deleted grants."

        user, session = dummy.user, dummy.session
        documents = dummy.get_documents(level=Level.view, n=3)
        uuid_document = Document.resolve_uuid(session, documents)
        uuid_document_list = list(uuid_document)

        grants = tuple(dummy.get_document_grant(dd) for dd in documents)
        assert (n := len(grants)) > 0

        for gg in grants:
            gg.deleted = True
            assert gg.uuid_user == user.uuid
            assert gg.pending is False
            assert gg.uuid_document in uuid_document

        session.add_all(grants)
        session.commit()

        uuid_document = Document.resolve_uuid(session, documents)
        uuid_grant = Grant.resolve_uuid(session, grants)
        uuid_document_list = list(uuid_document)

        # NOTE: Read! There should be nothing.
        fn_read = requests.grants.users.read
        res_read_pending, res_read = await asyncio.gather(
            fn_read(user.uuid, uuid_document=uuid_document_list, pending=True),
            fn_read(user.uuid, uuid_document=uuid_document_list, pending=False),
        )
        if err := self.check_status(requests, res_read_pending):
            raise err
        elif err := self.check_status(requests, res_read):
            raise err

        data_read_pending = self.adapter.validate_json(res_read_pending.content)
        data_read = self.adapter.validate_json(res_read.content)
        assert data_read_pending.kind is None
        assert data_read.kind is None

        # NOTE: These are deleted, should get a 400 for trying to overwrite
        #       without force.
        assert uuid_grant is not None
        httperr = mwargs(
            ErrDetail[ErrAssocRequestMustForce],
            detail=mwargs(
                ErrAssocRequestMustForce,
                msg=ErrAssocRequestMustForce._msg_force,
                kind_source=KindObject.user,
                kind_target=KindObject.document,
                kind_assoc=KindObject.grant,
                uuid_source=user.uuid,
                uuid_target=uuid_document,
                uuid_assoc=uuid_grant,
            ),
        )
        assert httperr.detail.uuid_assoc is not None

        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res, 400, err=httperr):
            raise err

        # NOTE: Adding the force parameter should not work, user will delete
        #       own existing.
        res = await fn(user.uuid, uuid_document=uuid_document_list, force=True)
        if err := self.check_status(requests, res, 400):
            raise err

        detail: Dict[str, str]
        assert isinstance(detail := res.json(), dict)

        msg: str | None
        if (msg := detail.get("msg")) is None:
            raise AssertionError("Response missing message.")

        assert msg.startswith("This request results in user deleting own ")
        assert msg.endswith("done by directly deleting these grants.")

    @pytest.mark.asyncio
    async def test_success_200_ideal(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test requesting a grant after grants cleared."

        user, session = dummy.user, dummy.session
        documents = dummy.get_documents(10, GetPrimaryKwargs(deleted=False), other=True)
        uuid_document = Document.resolve_uuid(session, documents)
        uuid_document_list = list(uuid_document)
        n = len(uuid_document_list)

        # NOTE: Cleanup deleted grants.
        q_grants = (
            select(Grant)
            .join(User)
            .join(Document)
            .where(User.uuid == user.uuid, Document.uuid.in_(uuid_document))
        )
        grant_rm = tuple(session.scalars(q_grants))
        for gg in grant_rm:
            session.delete(gg)

        session.commit()

        # NOTE: Read. Should be nothing.
        fn_read = requests.grants.users.read
        res_read_pending, res_read = await asyncio.gather(
            fn_read(user.uuid, uuid_document=uuid_document_list, pending=True),
            fn_read(user.uuid, uuid_document=uuid_document_list, pending=False),
        )

        if err := self.check_status(requests, res_read_pending):
            raise err
        elif err := self.check_status(requests, res_read):
            raise err

        data_read_pending = self.adapter.validate_json(res_read_pending.content)
        data_read = self.adapter.validate_json(res_read.content)
        assert data_read_pending.kind is None
        assert data_read.kind is None

        # NOTE: Request grants.
        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document_list)

        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        requests.context.console_handler.print_yaml(data.model_dump(mode="json"))
        assert data.events
        assert len(data.events) == 1
        assert len(data.events[0].children) == n
        assert len(data.data) == n

        session.reset()

        for item in data.data:
            item_from_db = session.get(Grant, item.uuid)

            assert item_from_db is not None
            assert item.pending and item_from_db.pending
            # assert not item_from_db.deleted

            assert item.pending_from == item_from_db.pending_from == PendingFrom.granter

        # NOTE: Read again.
        res_read_pending, res_read = await asyncio.gather(
            fn_read(
                user.uuid,
                uuid_document=list(uuid_document),
                pending=True,
            ),
            fn_read(
                user.uuid,
                uuid_document=list(uuid_document),
                pending=False,
            ),
        )

        if err := self.check_status(requests, res_read_pending):
            raise err
        elif err := self.check_status(requests, res_read):
            raise err

        data_read_pending = self.adapter.validate_json(res_read_pending.content)
        data_read = self.adapter.validate_json(res_read.content)

        assert data_read.kind is None
        assert data_read_pending.kind is KindObject.grant
        assert len(data_read_pending.data) == n

        # NOTE: Indempotent.
        res = await fn(user.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None

        assert len(data.events) == 1
        assert not len(data.events[0].children)

    # NOTE: Not too sure about this one. For now users can request access so
    #       long as they know the document uuid.
    @pytest.mark.skip
    async def test_forbidden_403_only_public_documents(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        """Test requesting a grant on a public document.

        Cannot ask for access to a private document, but filtering by private
        documents should be allowed for all other endpoint methods.
        """
        assert False


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUsersGrantsRead(CommonUsersGrantsTests):
    method = HTTPMethod.GET

    def fn(self, requests: Requests):
        return requests.grants.users.read

    @pytest.mark.asyncio
    async def test_success_200_random_documents(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
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
        documents = dummy.get_documents(5, kwargs, other=True)

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
    async def test_success_200_dne_documents(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Like `test_success_200_random_documents` but gaurenteed empty."""

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
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Test can read user pending grants for private documents."""

        user = dummy.user
        kwargs = GetPrimaryKwargs(public=False)
        documents = dummy.get_documents(1, kwargs, level=Level.view)
        uuid_document = list(Document.resolve_uuid(dummy.session, documents))

        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res, 200):
            raise err

        self.adapter.validate_json(res.content)

    # NOTE: The `pending` filter only works when `uuid_document` is not
    #       specified.
    @pytest.mark.parametrize("include_uuids", (0, 1))
    @pytest.mark.asyncio
    async def test_success_200_pending(
        self, dummy: DummyProvider, requests: Requests, count: int, include_uuids
    ):
        user = dummy.user
        fn = self.fn(requests)

        if include_uuids:
            docs = dummy.get_documents(
                n=1,
                level=Level.view,
                exclude_pending=True,
            )
            uuid_document = list(Document.resolve_uuid(dummy.session, docs))
        else:
            uuid_document = None

        count_nonempty = 0
        for pending in map(bool, (0, 1)):
            res = await fn(user.uuid, pending=pending, uuid_document=uuid_document)
            if err := self.check_status(requests, res):
                raise err

            data = self.adapter.validate_json(res.content)
            if data.kind is None:
                continue

            self.check_data(dummy, data, pending=pending)
            count_nonempty += 1

        if not count_nonempty:
            raise AssertionError("All empty.")

    @pytest.mark.asyncio
    async def test_success_200_pending_from(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Test the `pending_from` query parameter."""

        user = dummy.user
        fn = self.fn(requests)

        count_nonempty = 0
        for pending_from in list(PendingFrom):
            res = await fn(user.uuid, pending_from=PendingFromStr[pending_from.name])
            if err := self.check_status(requests, res, 200):
                raise err

            # pending_from = PendingFrom[res.request.url.params["pending_from"]]
            data = self.adapter.validate_json(res.content)

            if data.kind is None:
                continue

            self.check_data(dummy, data)
            bad = tuple(
                item
                for item in data.data
                if item.pending_from.name != pending_from.name
            )
            if len(bad):
                bad = tuple(item.model_dump(mode="json") for item in bad)
                msg = json.dumps(bad, indent=2, default=str)
                msg = f"Found unexpected values for `pending_from` (expected `{pending_from}`) in `{msg}`."
                raise AssertionError(msg)
            count_nonempty += 1

        if not count_nonempty:
            raise AssertionError("All empty.")

    @pytest.mark.asyncio
    async def test_success_200_level(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        user = dummy.user
        fn = self.fn(requests)

        levels = list(Level)
        responses = await asyncio.gather(
            *(fn(user.uuid, level=LevelStr[level.name]) for level in levels)
        )

        for level, res in zip(levels, responses):
            if err := self.check_status(requests, res):
                raise err

            data = self.adapter.validate_json(res.content)
            self.check_data(dummy, data, level=level)


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUsersGrantsReject(CommonUsersGrantsTests):
    method = HTTPMethod.DELETE

    def fn(self, requests: Requests):
        return requests.grants.users.reject

    @pytest.mark.asyncio
    async def test_success_200_ideal(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """User can remove own grants."""

        user, session = dummy.user, dummy.session
        user.deleted = False
        session.add(user)

        documents = dummy.get_documents(level=Level.view, n=5)
        uuid_document = Document.resolve_uuid(session, documents)
        uuid_document_list = list(uuid_document)

        # NOTE: Ensure all grants active.
        q_grants = (
            select(Grant)
            .join(User)
            .join(Document)
            .where(User.uuid == user.uuid, Document.uuid.in_(uuid_document))
        )
        grants = tuple(session.scalars(q_grants))
        for grant in grants:
            grant.deleted = False
            grant.pending = False
            session.add(grant)

        session.commit()

        # NOTE: Try reading to start with.
        fn_read = requests.grants.users.read
        res_read = await fn_read(user.uuid, uuid_document=uuid_document_list)

        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind == KindObject.grant
        assert len(data.data) == (n := len(uuid_document_list))

        # NOTE: Delete (no force)
        fn = self.fn(requests)
        res = await fn(user.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert len(data.events) == 1
        assert len(data.events[0].children) == n
        assert len(data.data) == n

        # NOTE: Verify with database.
        session.reset()
        for grant in data.data:
            grant_db = session.get(Grant, grant.uuid)
            assert grant_db is not None
            assert grant_db.deleted

        # NOTE: Try reading again. There should be nothing.
        res_read = await fn_read(user.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind is None

        # NOTE: Try deleting again. Should do nothing.
        res = await fn(user.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.events) == 0

        # NOTE: Try force deleting now.
        res = await fn(user.uuid, uuid_document=uuid_document_list, force=True)
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.grant
        assert len(data.data) == n
        assert len(data.events) == 1
        assert len(data.events[0].children) == n

        # NOTE: Verify with database.
        session.reset()
        for grant in data.data:
            grant_db = session.get(Grant, grant.uuid)
            assert grant_db is None


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUsersGrantsAccept(CommonUsersGrantsTests):
    method = HTTPMethod.PATCH

    def fn(self, requests: Requests):
        return requests.grants.users.accept

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """User can accept own grants."""

        session = dummy.session
        documents = dummy.get_documents(
            5,
            level=Level.view,
            pending=True,
            exclude_pending=False,
        )
        assert not any(dd.deleted for dd in documents)
        uuid_document = list(Document.resolve_uuid(dummy.session, documents))

        dummy.user.deleted = False
        session.add(dummy.user)

        grants = []
        for dd in documents:
            grant = dummy.get_document_grant(dd)
            if grant.pending_from == PendingFrom.created:
                continue

            grant.pending_from = PendingFrom.grantee
            assert grant.pending
            session.add(grant)
            grants.append(grant)

        session.commit()

        # NOTE: Cannot read pending unless specified.
        fn_read = requests.grants.users.read
        res_read = await fn_read(
            dummy.user.uuid, pending=False, uuid_document=uuid_document
        )
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert not len(data.data)
        assert data.kind is None

        # NOTE: Now with pending true
        fn_read = requests.grants.users.read
        res_read = await fn_read(
            dummy.user.uuid, pending=True, uuid_document=uuid_document
        )
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert (n := len(data.data)) == len(documents)
        assert data.kind is KindObject.grant

        # NOTE: Accept grants.
        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        dummy.session.reset()
        self.check_data(dummy, data, pending=False)

        # NOTE: Check with database.
        q_grants = dummy.user.q_select_grants(
            uuid_document,  # type: ignore
            exclude_deleted=False,
            exclude_pending=False,
        )
        grants = tuple(session.scalars(q_grants))
        assert len(grants) == len(uuid_document)

        still_pending = tuple(grant for grant in grants if grant.pending)
        if m := len(still_pending):
            msg = "Failed to move all grants from pending state. "
            msg += f"`{m}` of `{n}` grants still remain pending."
            raise AssertionError(msg)

        # NOTE: Should be able to read these grants after
        res_read = await fn_read(dummy.user.uuid, uuid_document=uuid_document)
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind == KindObject.grant

        # NOTE: Should not be able to read these grants after
        res_read = await fn_read(
            dummy.user.uuid, uuid_document=uuid_document, pending=True
        )
        if err := self.check_status(requests, res_read):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind is None

        # NOTE: Indempotent
        res = await fn(dummy.user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.events) == 1

    @pytest.mark.asyncio
    async def test_success_200_uuid_document_dne(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Test filtering by using fake document uuids."""
        uuid_document = [secrets.token_urlsafe(9) for _ in range(5)]

        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, uuid_document=uuid_document)

        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert not len(data.data)
        assert len(data.events) == 1  # Only the base event.

    @pytest.mark.asyncio
    async def test_forbidden_403_pending_from(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        """Test that grants with ``pending_from != granter`` cannot be approved
        with this endpoint.
        """

        session = dummy.session
        (document,) = dummy.get_documents(
            level=Level.view,
            n=1,
            pending=True,
            exclude_pending=False,
        )
        uuid_document = [Document.resolve_uuid(dummy.session, document)]

        grant = dummy.get_document_grant(document)
        assert grant.pending
        grant.pending_from = PendingFrom.granter
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, uuid_document=uuid_document)

        err_exp = mwargs(
            ErrDetail[ErrUpdateGrantPendingFrom],
            detail=mwargs(
                ErrUpdateGrantPendingFrom,
                msg=ErrUpdateGrantPendingFrom._msg_grantee,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
            ),
        )
        if err := self.check_status(requests, res, 403, err_exp):
            raise err
