# =========================================================================== #
import asyncio
import functools
import secrets
from typing import Callable, ClassVar, List, Self

import pytest
from pydantic import TypeAdapter
from sqlalchemy.sql.operators import op

# --------------------------------------------------------------------------- #
from app.controllers.access import H
from app.err import ErrAccessUser, ErrDetail, ErrObjMinSchema
from app.fields import ChildrenUser, KindObject
from app.models import Tables
from app.schemas import (
    AsOutput,
    CollectionSchema,
    DocumentMetadataSchema,
    DocumentSchema,
    KindNesting,
    OutputWithEvents,
    UserExtraSchema,
    UserSchema,
    mwargs,
)
from client.requests import Requests
from client.requests.base import MkRequestInstance
from client.requests.users import UserRequests
from tests.dummy import DummyProvider
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
    ):
        "Test unauthorized access."

        fn = self.fn(requests)

        requests.context.auth_exclude = True
        res = await fn(secrets.token_urlsafe())
        httperr = ErrDetail[str]( detail="Token required.")
        if err := self.check_status(requests, res, 401, httperr):
            raise err

        requests.context.auth_exclude = False

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
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
            )
        )
        if err:= self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
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
            )
        )
        if err := self.check_status(requests, res, 410, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):

        session = dummy.session
        user_other = next(user for user in dummy.get_users(2) if user != dummy.user)
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
            detail = ErrAccessUser(
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


class TestUserRead(CommonUserTests):
    method = H.GET
    adapter = TypeAdapter(AsOutput[UserExtraSchema])

    def fn(self, requests: Requests):
        return requests.users.read

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ): 
        "Test can read own user and public users."

        user, fn, session = dummy.user, self.fn(requests), dummy.session
        res = await fn(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user.uuid

        user_other = next(uu for uu in dummy.get_users(2) if uu != user)
        user_other.public = True
        session.add(user_other)
        session.commit()

        res = await fn(user_other.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user_other.uuid




class TestUserUpdate(CommonUserTests):
    method = H.PATCH

    def fn(self, requests: Requests, for_common: bool = True):
        if for_common:
            return functools.partial(
                requests.users.update,
                name="Updated via `tests.test_views.test_update::TestUserUpdate`."
            )

        return requests.users.update

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ): 
        user, fn = dummy.user, self.fn(requests, False)
        user_name_new = secrets.token_urlsafe()
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




class TestUserDelete(CommonUserTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        return requests.users.delete

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        session, user, fn = dummy.session, dummy.user, self.fn(requests)
        user.deleted = False
        session.add(user)
        session.commit()

        fn_read = requests.users.read

        res = await fn(user.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.user
        assert data.kind_nesting is None
        assert data.data.uuid == user.uuid

        res = await fn_read(user.uuid)
        if err := self.check_status(requests, res, 410):
            raise err
        

# --------------------------------------------------------------------------- #
# Search Stuff

class CommonUserSearchTests(CommonUserTests):
    is_search: ClassVar[bool] = True
    kind: ClassVar[KindObject]

    @pytest.mark.asyncio
    async def test_success_200_limit(self, dummy, requests):
        fn = self.fn(requests)
        res = await fn(dummy.user.uuid, limit=1)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is self.kind
        assert len(data.data) == 1


    @pytest.mark.asyncio
    async def test_success_200_randomize(self, dummy: DummyProvider, requests: Requests):
        fn = self.fn(requests)
        res1, res2 = await asyncio.gather(
            fn(dummy.user.uuid, limit=3, randomize=True),
            fn(dummy.user.uuid, limit=3, randomize=True),
        )
        if err := self.check_status(requests, res1):
            raise err
        elif err := self.check_status(requests, res2):
            raise err

        data1 = self.adapter.validate_json(res1.content)
        data2 = self.adapter.validate_json(res2.content)

        assert data1.kind == data2.kind == self.kind
        assert len(data1.data) == len(data2.data) == 3
        assert data1.data != data2.data

    @pytest.mark.asyncio
    async def test_success_200_uuids(self, dummy: DummyProvider, requests: Requests):

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
    async def test_success_200_name_like(self, dummy: DummyProvider, requests: Requests):
        # fn = self.fn(requests)
        # res = await fn(dummy.user.uuid)
        # if err := self.check_status(requests, res):
        #     raise err
        #
        # self.adapter.validate_json(res.content)
        ...

    @pytest.mark.asyncio
    async def test_success_200_description_like(self, dummy: DummyProvider, requests: Requests):
        assert False
        # fn = self.fn(requests)
        # res = await fn(dummy.user.uuid)
        # if err := self.check_status(requests, res):
        #     raise err
        #
        # self.adapter.validate_json(res.content)


class TestUsersSearch(CommonUserSearchTests):
    method = H.GET
    kind = KindObject.user
    adapter = TypeAdapter(AsOutput[List[UserSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[UserSchema]])

    def fn(self, requests: Requests):
        requests.users.search
        return functools.partial(
            requests.users.search,
            child=ChildrenUser.users
        )

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        assert False


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

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        assert False


class TestUserCollectionsSearch(CommonUserSearchTests):
    method = H.GET
    kind = KindObject.collection
    adapter = TypeAdapter(AsOutput[List[CollectionSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[CollectionSchema]])

    def fn(self, requests: Requests):
        requests.users.search
        return functools.partial(
            requests.users.search,
            child=ChildrenUser.collections
        )

    @pytest.mark.asyncio
    async def test_success_200(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        assert False


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
