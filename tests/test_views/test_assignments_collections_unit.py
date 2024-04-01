# =========================================================================== #
from typing import List

import pytest
from pydantic import TypeAdapter

# --------------------------------------------------------------------------- #
from app.schemas import AsOutput, AssignmentSchema, GrantSchema, OutputWithEvents
from client.requests import Requests
from tests.dummy import DummyProvider
from tests.test_views.util import BaseEndpointTest


class CommonAssignmentsCollectionsTests(BaseEndpointTest):
    adapter = TypeAdapter(AsOutput[List[AssignmentSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[GrantSchema]])

    @pytest.mark.asyncio
    async def test_deleted_410(self, dummy: DummyProvider, requests: Requests):
        assert False

    @pytest.mark.asyncio
    async def test_not_found_404(self, dummy: DummyProvider, requests: Requests):
        assert False

    @pytest.mark.asyncio
    async def test_unauthorized_401(self, dummy: DummyProvider, requests: Requests):
        assert False


class TestAssignmentsCollectionsRead(CommonAssignmentsCollectionsTests):
    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        (collection,) = dummy.get_user_collections(1)
        assert not collection.deleted
        session = dummy.session

        fn = self.fn(requests)

        # NOTE: Providing no parameters should return all assignments.
        res = await fn(collection.uuid)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter.validate_json(res.content)

        assignment_uuids: Set[str]
        q_assignment_uuids = select(Assignment.uuid).where(
            Assignment.id_collection == collection.uuid, Assignment.deleted == false()
        )
        assignment_uuids = set(session.scalars(q_assignment_uuids))

        for assignment in data.data:
            assert assignment.uuid in assignment_uuids
            assert not assignment.deleted

        assert len(data.data) == len(assignment_uuids)

        # NOTE: Adding limit should limit the resources. Randomize should
        #       gaurentee different order.
        limit = 10
        ress = await asyncio.gather(
            fn(collection.uuid, limit=limit),
            fn(collection.uuid, limit=limit, randomize=True),
            fn(collection.uuid, limit=limit, randomize=True),
        )
        if err := self.check_status(requests, ress, 200):
            raise err

        dd = tuple(self.adapter.validate_json(res.content) for res in ress)
        data_ordered, data_rand1, data_rand2 = dd

        assert len(data_ordered) == len(data_rand1) == len(data_rand2)
        assert data_ordered != data_rand1 != data_rand2


class TestAssignmentsCollectionsDelete(CommonAssignmentsCollectionsTests):
    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False


class TestAssignmentsCollectionsCreate(CommonAssignmentsCollectionsTests):
    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        assert False
