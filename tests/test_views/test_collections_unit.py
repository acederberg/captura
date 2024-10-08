# =========================================================================== #
import asyncio
import functools
import secrets
from http import HTTPMethod
from typing import Any, Awaitable, Callable, ClassVar, Concatenate, Dict, List

import httpx
import pytest
from pydantic import TypeAdapter
from sqlalchemy import false, select

# --------------------------------------------------------------------------- #
from captura.controllers.access import H
from captura.err import ErrAccessCollection, ErrDetail, ErrObjMinSchema
from captura.fields import KindObject
from captura.models import Assignment, Collection, Document, uuids
from captura.schemas import (
    AsOutput,
    AssignmentSchema,
    CollectionSchema,
    OutputWithEvents,
    mwargs,
)
from legere.requests import Requests
from legere.requests.base import P_Wrapped
from simulatus import DummyProvider
from tests.conftest import COUNT
from tests.test_views.util import BaseEndpointTest, BaseEndpointTestPrimaryCreateMixins


class CommonCollectionsTests(BaseEndpointTest):
    method: ClassVar[HTTPMethod]
    adapter = TypeAdapter(AsOutput[CollectionSchema])
    adapter_w_events = TypeAdapter(OutputWithEvents[CollectionSchema])

    @pytest.mark.asyncio
    async def test_deleted_410(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        # NOTE: Tried using `pytest.mark.skip` but marks all as bad.
        if self.method == HTTPMethod.POST:
            msg = "This test should not run for tests with `method=POST`."
            raise AttributeError(msg)

        (collection,), session = dummy.get_collections(1), dummy.session
        collection.deleted = True
        session.add(collection)
        session.commit()

        fn = self.fn(requests)
        res = await fn(collection.uuid)
        errhttp = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=collection.uuid,
                kind_obj=KindObject.collection,
            ),
        )
        if err := self.check_status(requests, res, 410, errhttp):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        if self.method == HTTPMethod.POST:
            msg = "This test should not run for tests with `method=POST`."
            raise AttributeError(msg)

        uuid_collection = secrets.token_urlsafe(9)
        fn = self.fn(requests)
        res = await fn(uuid_collection)
        errhttp = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_collection,
                kind_obj=KindObject.collection,
            ),
        )
        if err := self.check_status(requests, res, 404, errhttp):
            raise err

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (collection,) = dummy.get_collections(1)
        fn = self.fn(requests)

        assert requests.context.auth_exclude is False
        requests.context.auth_exclude = True
        res = await fn(collection.uuid)
        requests.context.auth_exclude = False

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        if self.method == HTTPMethod.POST:
            msg = "This test should not run for tests with `method=POST`."
            raise AttributeError(msg)

        user, session = dummy.user, dummy.session
        user_other = next(
            (item for item in dummy.get_users(2) if item.uuid != user.uuid)
        )

        (collection,) = dummy.get_collections(n=1)
        collection.public = True
        collection.deleted = False
        collection.uuid_user = user_other.uuid
        session.add(collection)
        session.commit()

        fn = self.fn(requests)
        res = await fn(collection.uuid)
        err_content = mwargs(
            ErrDetail[ErrAccessCollection],
            detail=ErrAccessCollection(
                msg=ErrAccessCollection._msg_modify,
                uuid_collection=collection.uuid,
                uuid_user_token=user.uuid,
            ),
        )

        # Should not be able to access unless get and public
        if self.method != H.GET:
            if err := self.check_status(requests, res, 403, err_content):
                raise err
            return

        if err := self.check_status(requests, res, 200):
            raise err

        collection.public = False
        session.add(collection)
        session.commit()

        err_content = mwargs(
            ErrDetail[ErrAccessCollection],
            detail=ErrAccessCollection(
                msg=ErrAccessCollection._msg_private,
                uuid_collection=collection.uuid,
                uuid_user_token=user.uuid,
            ),
        )
        res = await fn(collection.uuid)
        if err := self.check_status(requests, res, 403, err_content):
            raise err

    # NOTE: NOT NECESSARY! id_user cannot be null any more.
    # @pytest.mark.asyncio
    # async def test_teapot_418_homeless(self, dummy: DummyProvider, requests: Requests, count: int):
    #
    #     (collection,), session = dummy.get_collections(1), dummy.session
    #     collection_id_user = collection.id_user
    #     collection.id_user = None
    #
    #     session.add(collection)
    #     session.commit()


@pytest.mark.parametrize(
    "count",
    [count for count in range(COUNT)],
)
class TestCollectionsRead(CommonCollectionsTests):
    method = H.GET

    def fn(self, requests: Requests):
        return requests.collections.read

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (collection,), session = dummy.get_collections(1), dummy.session
        fn = self.fn(requests)

        # Test reading a public collection not ownend
        collection.public = not True
        collection.deleted = False
        session.commit()
        session.expire(collection)

        res = await fn(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.collection

        # Test reading a public collection not ownend
        collection.public = True
        collection.uuid_user = next(
            uu.uuid for uu in dummy.get_users(2) if uu.uuid != dummy.user.uuid
        )
        session.add(collection)
        session.commit()

        res = await fn(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.collection


def add_uuid_placeholder(
    fn: Callable[P_Wrapped, Awaitable[httpx.Response]], mixins: Dict[str, Any]
) -> Callable[Concatenate[Any, P_Wrapped], Awaitable[httpx.Response]]:
    async def fn_(
        uuid_placeholder: Any,
        *args: P_Wrapped.args,
        **kwargs: P_Wrapped.kwargs,
    ) -> httpx.Response:
        # =========================================================================== #
        from copy import copy

        mm = copy(mixins)
        mm.update(kwargs)
        return await fn(*args, **mm)

    return fn_


@pytest.mark.parametrize(
    "count",
    [count for count in range(COUNT)],
)
class TestCollectionsCreate(
    BaseEndpointTestPrimaryCreateMixins,
    CommonCollectionsTests,
):
    method = H.POST

    def fn(self, requests: Requests, for_common: bool = True):
        fn_fn = requests.collections.create
        if for_common:
            return add_uuid_placeholder(
                fn_fn,
                {
                    "description": f"From `{self.__class__.__name__}`.",
                    "name": f"Test {secrets.token_urlsafe(8)}",
                    "public": True,
                },
            )

        return fn_fn

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        # fn = self.fn(requests)
        # ^^^^^^^^^^^^^^^^^^^^^^ typehints suck

        # NOTE: Create and verify with db.
        fn = requests.collections.create
        name = f"Test {secrets.token_urlsafe(8)}"
        description = "Generated in `TestCollectionsCreate.test_success_200`"
        public = True

        res = await fn(name=name, description=description, public=public)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)

        assert data.data.uuid
        dummy.session.reset()
        collection = Collection.if_exists(dummy.session, data.data.uuid)

        assert data.kind == KindObject.collection
        assert data.data.description == description == collection.description
        assert data.data.name == name == collection.name
        assert data.data.public == collection.public

        # NOTE: Verify with read.
        fn_read = requests.collections.read
        res = await fn_read(data.data.uuid)
        if err := self.check_status(requests, res):
            raise err

        data_read = self.adapter.validate_json(res.content)
        assert data_read.data == data.data


# NOTE: These do not apply to this endpoint since it accepts no uuid.
# test_deleted_410 = pytest.mark.skip(TestCollectionsCreate.test_deleted_410)
# test_not_found_404 = pytest.mark.skip(TestCollectionsCreate.test_not_found_404)
# test_forbidden_403 = pytest.mark.skip(TestCollectionsCreate.test_forbidden_403)


@pytest.mark.parametrize(
    "count",
    [count for count in range(COUNT)],
)
class TestCollectionsUpdate(CommonCollectionsTests):
    method = H.PATCH

    # NOTE: Because this function is intended for the tests in `CommonCollectionsTests` and requires at least on argument.
    def fn(self, requests: Requests, for_common: bool = True):
        fn_ = requests.collections.update
        if for_common:
            return functools.partial(fn_, uuid_user="000-000-000")
        return fn_

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        user, session = dummy.user, dummy.session
        (collection,) = dummy.get_collections(1)
        collection.public = True
        session.add(collection)
        session.commit()
        session.expire(collection)

        fn, fn_read = self.fn(requests, False), requests.collections.read

        # NOTE: Verify can read and update description.
        res = await fn_read(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is KindObject.collection

        description_new = secrets.token_urlsafe(9)
        res = await fn(collection.uuid, description=description_new)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is KindObject.collection
        assert len(data.events) == 1
        assert len(data.events[0].children) == 1
        assert data.data.description == description_new

        # NOTE: Verify with database and by reading.
        # session.expire(collection)
        # assert collection.description == description_new

        res = await fn_read(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind_nesting is None
        assert data.kind is KindObject.collection
        assert data.data.description == description_new
        assert data.data.uuid_user == user.uuid  # For next test.

        # NOTE: Transfer ownership.
        user_other = next((uu for uu in dummy.get_users(2) if uu.uuid != user.uuid))
        res = await fn(collection.uuid, uuid_user=user_other.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind_nesting is None
        assert data.kind is KindObject.collection
        assert data.data.uuid_user == user_other.uuid
        assert len(data.events) == 1
        # requests.context.console_handler.print_json(data.model_dump(mode="json"))
        assert len(data.events[0].children) == 1

        # NOTE: Verify with database and via read
        # session.refresh(collection)
        # assert collection.uuid_user == user_other.uuid

        res = await fn_read(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind_nesting is None
        assert data.kind == KindObject.collection
        assert data.data.uuid_user == user_other.uuid


@pytest.mark.parametrize(
    "count",
    [count for count in range(COUNT)],
)
class TestCollectionsDelete(CommonCollectionsTests):
    method = H.DELETE

    adapter_assignments = TypeAdapter(AsOutput[List[AssignmentSchema]])

    def fn(self, requests: Requests):
        return requests.collections.delete

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (collection,), session = dummy.get_collections(1), dummy.session
        assert not collection.deleted
        assert collection.uuid_user == dummy.user.uuid
        fn, fn_read = self.fn(requests), requests.collections.read
        fn_read_assignments = requests.assignments.collections.read

        # NOTE: Read existing assignments, count existing assignments.
        q_assignments = (
            select(Assignment)
            .join(Collection)
            .join(Document)
            .where(
                Collection.uuid == collection.uuid,
                Document.deleted == false(),
                Collection.deleted == false(),
            )
        )
        uuid_assignments = uuids(tuple(session.scalars(q_assignments)))
        assert (n_assignments := len(uuid_assignments)) > 0

        res = await fn_read_assignments(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data_read = self.adapter_assignments.validate_json(res.content)
        # requests.context.console_handler.print_yaml(
        #     data=data_read.model_dump(mode="json")
        # )
        assert data_read.kind == KindObject.assignment
        assert len(data_read.data) == n_assignments

        # NOTE: Do delete.
        res = await fn(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        session.refresh(collection)

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.collection
        assert data.data.uuid == collection.uuid
        assert len(data.events) == 1

        # NOTE: Events checking will be implemented on its own and then added
        #       subsequently.
        # requests.context.console_handler.print_yaml(
        #     data=[
        #         item.model_dump(mode="json")
        #         for item in TypeAdapter(List[EventSchema]).validate_python(
        #             data.events[0].children
        #         )
        #     ]
        # )
        # assert len(event_assignments_bulk := data.events[0].children) == 1
        #
        # requests.context.console_handler.print_json(
        #     data=[
        #         item.model_dump(mode="json")
        #         for item in TypeAdapter(List[EventSchema]).validate_python(
        #             event_assignments_bulk[0].children
        #         )
        #     ]
        # )
        # assert len(event_assignments := event_assignments_bulk[0].children) == 1
        # assert len(event_assignments[0].children) == n_assignments
        #
        # NOTE: All assignments should be soft deleted.
        session.reset()
        q = select(Assignment).where(Assignment.uuid.in_(uuid_assignments))
        assignments = tuple(session.scalars(q))

        if n_bad := len(
            bad := tuple(
                session.refresh(assignment) or assignment.uuid
                for assignment in assignments
                if not assignment.deleted
            )
        ):
            raise AssertionError(
                "No assignments should remain outside of deleted state. Found "
                f"`{n_bad}/{n_assignments}` not deleted. Bad uuids: `{bad}`."
            )

        # NOTE: Not indempotent, should get 410. Should not be able to read.
        res, res_read, res_read_assignments = await asyncio.gather(
            fn(collection.uuid),
            fn_read(collection.uuid),
            fn_read_assignments(collection.uuid),
        )

        if err := self.check_status(requests, res, 410):
            raise err
        elif err := self.check_status(requests, res_read, 410):
            raise err
        elif err := self.check_status(requests, res_read_assignments, 410):
            raise err

        # NOTE: Force delete.
        res = await fn(collection.uuid, force=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.collection
        assert data.data.uuid == collection.uuid
        assert len(data.events) == 1
        # assert len(event_assignments_bulk := data.events[0].children) == 1
        # assert len(event_assignments_bulk[0].children) == n_assignments

        # NOTE: Collection no longer exists.
        res, res_read, res_read_assignments = await asyncio.gather(
            fn(collection.uuid),
            fn_read(collection.uuid),
            fn_read_assignments(collection.uuid),
        )

        if err := self.check_status(requests, res, 404):
            raise err
        elif err := self.check_status(requests, res_read, 404):
            raise err
        elif err := self.check_status(requests, res_read_assignments, 404):
            raise err
