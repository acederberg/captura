# =========================================================================== #
import asyncio
import functools
import re
import secrets
from typing import Callable, ClassVar, List, Self

import pytest
from pydantic import TypeAdapter
from sqlalchemy import func, select
from sqlalchemy.sql.operators import op

# --------------------------------------------------------------------------- #
from app.controllers.access import H
from app.err import ErrAccessUser, ErrDetail, ErrObjMinSchema
from app.fields import ChildrenUser, KindObject
from app.models import Tables, User
from app.schemas import (
    AsOutput,
    CollectionMetadataSchema,
    CollectionSchema,
    DocumentMetadataSchema,
    OutputWithEvents,
    UserExtraSchema,
    UserSchema,
    mwargs,
)
from client.requests import Requests
from dummy import DummyProvider
from dummy.mk import fkit
from dummy.reports import ReportController
from tests.test_views.util import BaseEndpointTest


class CommonUserTests(BaseEndpointTest):
    is_search: ClassVar[bool] = False
    method: ClassVar[H]
    adapter = TypeAdapter(AsOutput[UserSchema])
    adapter_w_events = TypeAdapter(OutputWithEvents[UserSchema])
    # fn: ClassVar[Callable[[Requests], MkRequestInstance[UserRequests, ...]]]

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test unauthorized access."

        fn = self.fn(requests)

        requests.context.auth_exclude = True
        res = await fn(secrets.token_urlsafe(8))
        httperr = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, httperr):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test only user can access."
        fn = self.fn(requests)
        res = await fn(uuid := secrets.token_urlsafe(9))
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid,
                kind_obj=KindObject.user,
            ),
        )
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test no such user."
        session = dummy.session
        user_other = next(uu for uu in dummy.get_users(2) if uu != dummy.user)
        user_other.deleted = True
        session.add(user_other)
        session.commit()

        fn = self.fn(requests)
        res = await fn(user_other.uuid)
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=user_other.uuid,
                kind_obj=KindObject.user,
            ),
        )
        if err := self.check_status(requests, res, 410, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        session = dummy.session
        user_other = next(user for user in dummy.get_users(2) if user != dummy.user)
        user_other.deleted = False
        if self.method == H.GET:
            user_other.public = False
            msg = ErrAccessUser._msg_private
        else:
            msg = ErrAccessUser._msg_modify
            return
        session.add(user_other)
        session.commit()

        fn = self.fn(requests)
        res = await fn(user_other.uuid)
        httperr = mwargs(
            ErrDetail[ErrAccessUser],
            detail=ErrAccessUser(
                msg=msg,
                uuid_user=user_other.uuid,
                uuid_user_token=dummy.user.uuid,
            ),
        )
        if err := self.check_status(requests, res, 403, httperr):
            raise err

        if not self.is_search:
            user_other.public = True
            session.add(user_other)
            session.commit()

            res = await fn(user_other.uuid)
            if err := self.check_status(requests, res):
                raise err


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUserRead(CommonUserTests):
    method = H.GET
    adapter = TypeAdapter(AsOutput[UserSchema])

    def fn(self, requests: Requests):
        return requests.users.read

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        "Test can read own user and public users."

        user, fn, session = dummy.user, self.fn(requests), dummy.session
        user.deleted = False
        session.add(user)
        session.commit()

        res = await fn(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user.uuid

        user_other = next(uu for uu in dummy.get_users(2) if uu != user)
        user_other.public = True
        user_other.deleted = False
        session.add(user_other)
        session.commit()

        res = await fn(user_other.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user_other.uuid


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUserUpdate(CommonUserTests):
    method = H.PATCH

    def fn(self, requests: Requests, for_common: bool = True):
        if for_common:
            return functools.partial(
                requests.users.update,
                name="Updated via `tests.test_views.test_update::TestUserUpdate`.",
            )

        return requests.users.update

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        user, fn = dummy.user, self.fn(requests, False)
        user_name_new = secrets.token_urlsafe(8)
        res = await fn(user.uuid, name=user_name_new)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.user
        assert len(data.events) == 1
        assert len(data.events[0].children) == 1
        assert data.data.name == user_name_new

        res = await requests.users.read(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.data.name == user_name_new


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUserDelete(CommonUserTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        return requests.users.delete

    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
        count: int,
    ):
        session, user = dummy.session, dummy.user
        fn, fn_read = self.fn(requests), requests.users.read

        # fmt_note = "{} report from `TestUserDelete.test_success_200`."
        # report_controller = ReportController(session)
        # report_initial = report_controller.create_user(
        #     user=user, note=fmt_note.format("initial")
        # )
        # session.add(report_initial)
        # session.commit()

        # NOTE: Verify can read.
        res = await fn_read(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user.uuid

        # NOTE: Do delete.
        res = await fn(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        assert res.json() is None

        # NOTE: Can no longer read.
        res = await fn_read(user.uuid)
        if err := self.check_status(requests, res, 410):
            raise err

        session.refresh(user)
        assert user.deleted

        # NOTE: Can force delete.
        res = await fn(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        q = select(func.count(User.uuid)).where(User.uuid == user.uuid)
        n = session.scalar(q)
        assert n is not None
        assert n == 0


# --------------------------------------------------------------------------- #
# Search Stuff


class CommonUserSearchTests(CommonUserTests):
    is_search: ClassVar[bool] = True
    kind: ClassVar[KindObject]

    @pytest.mark.asyncio
    async def test_success_200_limit(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, limit=1)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is self.kind
        assert len(data.data) == 1

    @pytest.mark.asyncio
    async def test_success_200_randomize(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        N = 25
        fn = self.fn(requests)
        res1, res2 = await asyncio.gather(
            fn(dummy.user.uuid, limit=N, randomize=True),
            fn(dummy.user.uuid, limit=N, randomize=True),
        )
        if err := self.check_status(requests, res1):
            raise err
        elif err := self.check_status(requests, res2):
            raise err

        data1 = self.adapter.validate_json(res1.content)
        data2 = self.adapter.validate_json(res2.content)

        assert data1.kind == data2.kind == self.kind
        assert len(data1.data) == len(data2.data)
        assert data1.data != data2.data

    @pytest.mark.asyncio
    async def test_success_200_uuids(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        fn = self.fn(requests)

        # NOTE: Read w/o uuids
        res = await fn(dummy.user.uuid, limit=20, randomize=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == self.kind
        assert 0 < len(data.data) <= 20

        uuids = set(obj.uuid for obj in data.data)
        assert len(uuids)

        # NOTE: Use the ids as a filter.
        res = await fn(dummy.user.uuid, uuids=list(uuids), limit=20)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is self.kind
        assert 0 < len(data.data) <= len(uuids)

        uuids_recieves = set(item.uuid for item in data.data)
        bad = set(uuid for uuid in uuids_recieves if uuid not in uuids)

        if n := len(bad):
            m = len(uuids)
            raise AssertionError(
                f"Got `{n}` unexpected ids `{bad}` out of `{m}` ids requested"
                f"and items `{len(data.data)}` recieved.\n\n"
                f"Requested ids: `{uuids}`."
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("field", ("name_like", "description_like"))
    async def test_success_200_like(
        self, dummy: DummyProvider, requests: Requests, count: int, field: str
    ):
        fn = self.fn(requests)
        names = {fkit.word() for _ in range(25)}

        res = await asyncio.gather(
            *(fn(dummy.user.uuid, **{field: name}) for name in names)
        )
        errs = (self.check_status(requests, rr) for rr in res)
        if err := next((ee for ee in errs if ee is not None), None):
            raise err

        n_mt = 0
        for name_like, data in zip(
            names, (self.adapter.validate_json(rr.content) for rr in res)
        ):
            if data.kind is None:
                n_mt += 1
                continue

            assert data.kind == self.kind
            pattern = re.compile(f".*{name_like}.*", flags=re.I)
            attr = field.replace("_like", "")

            bad = tuple(
                item
                for item in data.data
                if pattern.search(getattr(item, attr)) is None
            )
            if n := len(bad):
                m = len(data.data)
                print(name_like)
                print(bad)
                msg = f"Recieved `{n}` unexpected items out of `{m}`."
                raise AssertionError(msg)

        if n_mt == 10:
            raise AssertionError("All filtered data is empty.")

    # @pytest.mark.asyncio
    # async def test_success_200_description_like(self, dummy: DummyProvider, requests: Requests, count: int):
    #     assert False
    #     # fn = self.fn(requests)
    #     # res = await fn(dummy.user.uuid)
    #     # if err := self.check_status(requests, res):
    #     #     raise err
    #     #
    #     # self.adapter.validate_json(res.content)


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUsersSearch(CommonUserSearchTests):
    method = H.GET
    kind = KindObject.user
    adapter = TypeAdapter(AsOutput[List[UserSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[UserSchema]])

    def fn(self, requests: Requests):
        requests.users.search
        return functools.partial(requests.users.search, child=ChildrenUser.users)

    # @pytest.mark.asyncio
    # async def test_success_200(
    #     self,
    #     dummy: DummyProvider,
    #     requests: Requests,
    # ):
    #     assert False


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUserDocumentsSearch(CommonUserSearchTests):
    method = H.GET
    kind = KindObject.document
    adapter = TypeAdapter(AsOutput[List[DocumentMetadataSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[DocumentMetadataSchema]])

    def fn(self, requests: Requests):
        requests.users.search
        return functools.partial(
            requests.users.search,
            child=ChildrenUser.documents,
            limit=5,
        )


@pytest.mark.parametrize(
    "dummy, requests, count",
    [(None, None, count) for count in range(5)],
    indirect=["dummy", "requests"],
)
class TestUserCollectionsSearch(CommonUserSearchTests):
    method = H.GET
    kind = KindObject.collection
    adapter = TypeAdapter(AsOutput[List[CollectionMetadataSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[CollectionMetadataSchema]])

    def fn(self, requests: Requests):
        requests.users.search
        return functools.partial(requests.users.search, child=ChildrenUser.collections)

    # @pytest.mark.asyncio
    # async def test_success_200(
    #     self,
    #     dummy: DummyProvider,
    #     requests: Requests,
    # ):
    #     assert False
    #


# class TestEditsSearch(CommonUserSearchTests):
#     method = H.GET
#     kind = KindObject.edit
#     adapter = TypeAdapter(AsOutput[List[CollectionSchema]])
#     adapter = TypeAdapter(OutputWithEvents[List[CollectionSchema]])
#
#     def fn(self, requests: Requests):
#         requests.users.search
#         return functools.partial(
#             requests.users.search,
#             child=ChildrenUser.edits
#         )
#
#     @pytest.mark.asyncio
#     async def test_success_200(
#         self,
#         dummy: DummyProvider,
#         requests: Requests,
#     ):
#         assert False
#
#
